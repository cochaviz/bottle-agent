package analysis

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/cochaviz/bottle/daemon"
)

var ErrDaemonUnavailable = errors.New("bottle daemon client is not configured")

// OrchestratorConfig tunes how aggressive the orchestrator operates.
type OrchestratorConfig struct {
	PollInterval time.Duration
	Logger       *slog.Logger
}

// Orchestrator keeps the daemon state in sync with the ledger.
type Orchestrator struct {
	ledger       *Ledger
	daemon       *daemon.Client
	pollInterval time.Duration
	logger       *slog.Logger
	triggerCh    chan struct{}
}

// NewOrchestrator wires the dependencies together.
func NewOrchestrator(ledger *Ledger, daemonClient *daemon.Client, cfg OrchestratorConfig) *Orchestrator {
	poll := cfg.PollInterval
	if poll <= 0 {
		poll = 5 * time.Second
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Orchestrator{
		ledger:       ledger,
		daemon:       daemonClient,
		pollInterval: poll,
		logger:       logger.With("component", "orchestrator"),
		triggerCh:    make(chan struct{}, 1),
	}
}

// Trigger requests a reconciliation cycle outside of the normal poll interval.
func (o *Orchestrator) Trigger() {
	select {
	case o.triggerCh <- struct{}{}:
	default:
	}
}

// startJob launches a new analysis job through the daemon client.
func (o *Orchestrator) startJob(ctx context.Context, opts StartOptions) (string, error) {
	if err := opts.Validate(); err != nil {
		return "", err
	}
	if ctx != nil {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}
	}
	if o.daemon == nil {
		if opts.ID == "" {
			opts.ID = generateDryRunID()
		}
		return opts.ID, nil
	}
	return o.daemon.StartAnalysis(opts.toDaemonRequest())
}

// stopJob requests the daemon to stop a running job.
func (o *Orchestrator) stopJob(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("id is required")
	}
	if ctx != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
	if o.daemon == nil {
		return nil
	}
	return o.daemon.StopAnalysis(id)
}

// listJobs returns the current runtime state from the daemon.
func (o *Orchestrator) listJobs(ctx context.Context) ([]RuntimeStatus, error) {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}
	if o.daemon == nil {
		return nil, nil
	}
	statuses, err := o.daemon.List()
	if err != nil {
		return nil, err
	}
	result := make([]RuntimeStatus, 0, len(statuses))
	for _, status := range statuses {
		result = append(result, RuntimeStatus{
			ID:        status.ID,
			Sample:    status.Sample,
			C2IP:      status.C2Ip,
			StartedAt: status.StartedAt,
			Running:   status.Running,
			Error:     status.Error,
		})
	}
	return result, nil
}

// inspectJob fetches the detailed state for a job directly from the daemon.
func (o *Orchestrator) inspectJob(ctx context.Context, id string) (*daemon.WorkerDetails, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("id is required")
	}
	if o == nil {
		return nil, errors.New("orchestrator is not configured")
	}
	if ctx != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}
	if o.daemon == nil {
		return nil, ErrDaemonUnavailable
	}
	details, err := o.daemon.Inspect(id)
	if err != nil {
		return nil, err
	}
	return &details, nil
}

// ListRuntime exposes the daemon worker statuses to callers.
func (o *Orchestrator) ListRuntime(ctx context.Context) ([]RuntimeStatus, error) {
	if o == nil {
		return nil, errors.New("orchestrator is not configured")
	}
	if o.daemon == nil {
		return nil, ErrDaemonUnavailable
	}
	return o.listJobs(ctx)
}

// InspectWorker returns the detailed state for a worker managed by the daemon.
func (o *Orchestrator) InspectWorker(ctx context.Context, id string) (*daemon.WorkerDetails, error) {
	if o == nil {
		return nil, errors.New("orchestrator is not configured")
	}
	return o.inspectJob(ctx, id)
}

// Run starts the reconciliation loop and blocks until the context is cancelled.
func (o *Orchestrator) Run(ctx context.Context) error {
	ticker := time.NewTicker(o.pollInterval)
	defer ticker.Stop()
	for {
		if err := o.reconcile(ctx); err != nil {
			o.logger.Error("reconcile failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		case <-o.triggerCh:
		}
	}
}

func (o *Orchestrator) reconcile(ctx context.Context) error {
	if o.ledger == nil {
		return errors.New("ledger is not configured")
	}
	if err := o.ledger.Reload(); err != nil {
		return fmt.Errorf("reload ledger: %w", err)
	}
	records := o.ledger.List()
	statuses, err := o.listJobs(ctx)
	if err != nil {
		return fmt.Errorf("list runtime state: %w", err)
	}
	statusByID := make(map[string]RuntimeStatus, len(statuses))
	for _, status := range statuses {
		statusByID[status.ID] = status
	}
	for _, rec := range records {
		status, exists := statusByID[rec.ID]
		if exists {
			if status.Running && rec.State != StateStale && rec.State != StateStopping {
				o.updateState(rec.ID, StateRunning, status.Error)
			} else if !status.Running {
				next := StateStopped
				if status.Error != "" {
					next = StateFailed
				}
				o.updateState(rec.ID, next, status.Error)
			}
		} else if rec.State == StateRunning {
			o.updateState(rec.ID, StateStopped, "")
		}
	}
	for _, rec := range o.ledger.List() {
		switch rec.State {
		case StateQueued:
			if o.ledger.HasBatchPredecessor(rec.ID) {
				continue
			}
			if err := o.maybeStart(ctx, rec); err != nil {
				o.logger.Error("failed to start analysis", "id", rec.ID, "error", err)
				_, _ = o.ledger.Update(rec.ID, func(r *Record) error {
					r.State = StateFailed
					r.LastError = err.Error()
					return nil
				})
			}
		case StateStale, StateStopping:
			status, exists := statusByID[rec.ID]
			if err := o.ensureStopped(ctx, rec, status, exists); err != nil {
				o.logger.Error("failed to stop analysis", "id", rec.ID, "error", err)
			}
		}
	}
	return nil
}

func (o *Orchestrator) updateState(id string, state State, errMsg string) {
	if state == "" {
		return
	}
	_, err := o.ledger.Update(id, func(r *Record) error {
		if r.State == StateStale && state == StateStopped {
			state = StateStopped
		}
		if r.State == state {
			if errMsg != "" && r.LastError != errMsg {
				r.LastError = errMsg
			}
			return nil
		}
		r.State = state
		r.LastError = errMsg
		return nil
	})
	if err != nil {
		o.logger.Warn("failed to update record state", "id", id, "error", err)
	}
}

func (o *Orchestrator) maybeStart(ctx context.Context, rec *Record) error {
	if rec == nil {
		return errors.New("record is nil")
	}
	if rec.SamplePath == "" {
		return fmt.Errorf("analysis %s has no sample path resolved yet", rec.ID)
	}
	opts := StartOptions{
		ID:              rec.ID,
		SamplePath:      rec.SamplePath,
		C2Address:       rec.C2Address,
		Instrumentation: rec.Instrumentation,
		SampleArgs:      rec.SampleArgs,
		SampleTimeout:   rec.SampleTimeout.Duration,
		SandboxTimeout:  rec.SandboxTimeout.Duration,
	}
	if err := opts.Validate(); err != nil {
		return err
	}
	if _, err := o.startJob(ctx, opts); err != nil {
		return err
	}
	startTime := time.Now().UTC()
	_, err := o.ledger.Update(rec.ID, func(r *Record) error {
		r.State = StateRunning
		if r.StartedAt.IsZero() {
			r.StartedAt = startTime
		}
		r.LastError = ""
		return nil
	})
	return err
}

func (o *Orchestrator) ensureStopped(ctx context.Context, rec *Record, status RuntimeStatus, exists bool) error {
	if rec == nil {
		return errors.New("record is nil")
	}
	if exists && status.Running {
		if err := o.stopJob(ctx, rec.ID); err != nil {
			return err
		}
		_, err := o.ledger.Update(rec.ID, func(r *Record) error {
			r.State = StateStopping
			return nil
		})
		return err
	}
	_, err := o.ledger.Update(rec.ID, func(r *Record) error {
		r.State = StateStopped
		return nil
	})
	return err
}
