package analysis

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cochaviz/bottle-warden/internal/appconfig"
)

// Monitor watches the Suricata eve.json log and marks analyses as stale if the
// configured inactivity windows are exceeded.
type Monitor struct {
	cfg          appconfig.MonitoringConfig
	ledger       *Ledger
	orchestrator *Orchestrator
	logger       *slog.Logger
}

// NewMonitor wires together the dependencies. Monitoring remains idle if the
// configuration is not active.
func NewMonitor(ledger *Ledger, orchestrator *Orchestrator, cfg appconfig.MonitoringConfig, logger *slog.Logger) *Monitor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Monitor{
		cfg:          cfg,
		ledger:       ledger,
		orchestrator: orchestrator,
		logger:       logger.With("component", "monitor"),
	}
}

// Run blocks until the context is cancelled.
func (m *Monitor) Run(ctx context.Context) error {
	if !m.cfg.Active() {
		m.logger.Info("monitor disabled")
		<-ctx.Done()
		return ctx.Err()
	}

	state := newMonitorState(m.ledger, m.orchestrator, m.cfg, m.logger)
	events := make(chan eveEvent, 256)

	go m.tailEVE(ctx, events)

	ticker := time.NewTicker(m.cfg.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case evt, ok := <-events:
			if !ok {
				return errors.New("eve monitor stopped")
			}
			state.handleEvent(evt)
		case <-ticker.C:
			state.checkAnalyses()
		}
	}
}

func (m *Monitor) tailEVE(ctx context.Context, out chan<- eveEvent) {
	for {
		file, err := os.Open(m.cfg.EVEPath)
		if err != nil {
			m.logger.Warn("eve.json open failed", "error", err)
			if !waitOrCancel(ctx, 5*time.Second) {
				return
			}
			continue
		}
		reader := bufio.NewReader(file)
		for {
			select {
			case <-ctx.Done():
				file.Close()
				return
			default:
			}
			line, err := reader.ReadBytes('\n')
			if len(line) > 0 {
				var event eveEvent
				if err := json.Unmarshal(bytes.TrimSpace(line), &event); err == nil {
					select {
					case out <- event:
					case <-ctx.Done():
						file.Close()
						return
					}
				}
			}
			if errors.Is(err, io.EOF) {
				if !waitOrCancel(ctx, 2*time.Second) {
					file.Close()
					return
				}
				continue
			}
			if err != nil {
				m.logger.Warn("eve.json read error", "error", err)
				break
			}
		}
		file.Close()
		if !waitOrCancel(ctx, 2*time.Second) {
			return
		}
	}
}

func waitOrCancel(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

type eveEvent struct {
	Timestamp string `json:"timestamp"`
	Host      string `json:"host"`
	Alert     *struct {
		SignatureID int `json:"signature_id"`
	} `json:"alert"`
}

func (e eveEvent) parsedTime() (time.Time, error) {
	if e.Timestamp == "" {
		return time.Time{}, errors.New("timestamp missing")
	}
	layouts := []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05.999999-0700",
		"2006-01-02T15:04:05-0700",
	}
	for _, layout := range layouts {
		if ts, err := time.Parse(layout, e.Timestamp); err == nil {
			return ts, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognized timestamp %q", e.Timestamp)
}

type monitorState struct {
	ledger       *Ledger
	orchestrator *Orchestrator
	cfg          appconfig.MonitoringConfig
	logger       *slog.Logger

	mu      sync.Mutex
	records map[string]*Record
}

func newMonitorState(ledger *Ledger, orchestrator *Orchestrator, cfg appconfig.MonitoringConfig, logger *slog.Logger) *monitorState {
	if logger == nil {
		logger = slog.Default()
	}
	state := &monitorState{
		ledger:       ledger,
		orchestrator: orchestrator,
		cfg:          cfg,
		logger:       logger,
	}
	_ = state.refreshLocked()
	return state
}

func (m *monitorState) handleEvent(evt eveEvent) {
	if evt.Alert == nil || evt.Alert.SignatureID == 0 {
		return
	}
	sample := strings.TrimSpace(evt.Host)
	if sample == "" {
		return
	}
	timeout := m.cfg.TimeoutForSID(evt.Alert.SignatureID)
	if timeout <= 0 {
		return
	}
	ts, err := evt.parsedTime()
	if err != nil {
		m.logger.Warn("invalid eve timestamp", "error", err)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.records == nil || m.records[sample] == nil {
		if err := m.refreshLocked(); err != nil {
			m.logger.Warn("monitor refresh failed", "error", err)
			return
		}
	}
	rec := m.records[sample]
	if rec == nil || rec.State != StateRunning {
		return
	}
	sidKey := strconv.Itoa(evt.Alert.SignatureID)
	_, err = m.ledger.Update(rec.ID, func(r *Record) error {
		if r.LastAlertTimes == nil {
			r.LastAlertTimes = make(map[string]time.Time)
		}
		r.LastAlertTimes[sidKey] = ts
		return nil
	})
	if err != nil {
		m.logger.Warn("failed to update alert timestamp", "id", rec.ID, "error", err)
		return
	}
	if rec.LastAlertTimes == nil {
		rec.LastAlertTimes = make(map[string]time.Time)
	}
	rec.LastAlertTimes[sidKey] = ts
}

func (m *monitorState) checkAnalyses() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.refreshLocked(); err != nil {
		m.logger.Warn("monitor refresh failed", "error", err)
		return
	}
	now := time.Now()
	for _, rec := range m.records {
		start := rec.StartedAt
		if start.IsZero() {
			start = rec.CreatedAt
		}
		if m.cfg.AnalysisTimeout > 0 && now.Sub(start) > m.cfg.AnalysisTimeout {
			m.markStaleLocked(rec, fmt.Sprintf("analysis exceeded %s", m.cfg.AnalysisTimeout))
			continue
		}
		for _, rule := range m.cfg.Alerts {
			timeout := rule.Timeout
			if timeout <= 0 {
				timeout = m.cfg.DefaultTimeout
			}
			if timeout <= 0 {
				continue
			}
			var last time.Time
			if rec.LastAlertTimes != nil {
				last = rec.LastAlertTimes[strconv.Itoa(rule.SID)]
			}
			if last.IsZero() {
				last = start
			}
			if now.Sub(last) > timeout {
				m.markStaleLocked(rec, fmt.Sprintf("sid %d inactive for %s", rule.SID, timeout))
				break
			}
		}
	}
}

func (m *monitorState) refreshLocked() error {
	if m.ledger == nil {
		return errors.New("ledger not configured")
	}
	if err := m.ledger.Reload(); err != nil {
		return err
	}
	records := make(map[string]*Record)
	for _, rec := range m.ledger.List() {
		if rec.State == StateRunning {
			records[rec.SampleID] = rec
		}
	}
	m.records = records
	return nil
}

func (m *monitorState) markStaleLocked(rec *Record, reason string) {
	if rec == nil {
		return
	}
	_, err := m.ledger.Update(rec.ID, func(r *Record) error {
		if r.State == StateStale {
			return nil
		}
		r.State = StateStale
		r.LastError = reason
		if r.Metadata == nil {
			r.Metadata = make(map[string]string)
		}
		r.Metadata["stale_reason"] = reason
		return nil
	})
	if err != nil {
		m.logger.Warn("failed to mark analysis stale", "id", rec.ID, "error", err)
		return
	}
	m.logger.Info("marked analysis stale", "id", rec.ID, "reason", reason)
	if m.orchestrator != nil {
		m.orchestrator.Trigger()
	}
}
