package analysis

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// State describes the lifecycle state for an analysis entry that is persisted
// in the ledger.
type State string

const (
	StateUnknown  State = "unknown"
	StateQueued   State = "queued"
	StateRunning  State = "running"
	StateStopping State = "stopping"
	StateStale    State = "stale"
	StateStopped  State = "stopped"
	StateFailed   State = "failed"
	StateComplete State = "completed"
)

// Active returns true if the state represents an analysis that should prevent
// other analyses of the same sample/C2 from running.
func (s State) Active() bool {
	switch s {
	case StateQueued, StateRunning, StateStopping:
		return true
	default:
		return false
	}
}

// Terminal reports whether the state no longer changes without an explicit
// user action.
func (s State) Terminal() bool {
	switch s {
	case StateStopped, StateFailed, StateComplete:
		return true
	default:
		return false
	}
}

// SourceType denotes the possible sources for a sample.
type SourceType string

const (
	SourceFile SourceType = "file"
	SourceURL  SourceType = "url"
	SourceHash SourceType = "hash"
)

// SourceSpec tracks how a sample should be retrieved.
type SourceSpec struct {
	Type  SourceType `json:"type"`
	Value string     `json:"value"`
}

// Validate ensures the source configuration is sane.
func (s SourceSpec) Validate() error {
	switch s.Type {
	case SourceFile, SourceURL, SourceHash:
	default:
		return fmt.Errorf("unsupported source type %q", s.Type)
	}
	if strings.TrimSpace(s.Value) == "" {
		return errors.New("source value is required")
	}
	return nil
}

// Duration wraps time.Duration to ensure we marshal and unmarshal using the
// standard duration string representation instead of raw nanoseconds.
type Duration struct {
	time.Duration
}

// MarshalJSON renders the duration as a Go duration string.
func (d Duration) MarshalJSON() ([]byte, error) {
	if d.Duration == 0 {
		return json.Marshal("")
	}
	return json.Marshal(d.Duration.String())
}

// UnmarshalJSON accepts either a quoted duration string or a raw integer.
func (d *Duration) UnmarshalJSON(data []byte) error {
	var txt string
	if err := json.Unmarshal(data, &txt); err == nil {
		if strings.TrimSpace(txt) == "" {
			d.Duration = 0
			return nil
		}
		parsed, err := time.ParseDuration(txt)
		if err != nil {
			return err
		}
		d.Duration = parsed
		return nil
	}
	var raw int64
	if err := json.Unmarshal(data, &raw); err == nil {
		d.Duration = time.Duration(raw)
		return nil
	}
	return fmt.Errorf("invalid duration literal %q", string(data))
}

// Record is the persisted representation for an analysis entry in the ledger.
type Record struct {
	ID              string               `json:"id"`
	SampleID        string               `json:"sample_id"`
	SamplePath      string               `json:"sample_path,omitempty"`
	C2Address       string               `json:"c2_address,omitempty"`
	Instrumentation string               `json:"instrumentation,omitempty"`
	SampleArgs      []string             `json:"sample_args,omitempty"`
	SampleTimeout   Duration             `json:"sample_timeout"`
	SandboxTimeout  Duration             `json:"sandbox_timeout"`
	BatchID         string               `json:"batch_id,omitempty"`
	BatchPosition   int                  `json:"batch_position,omitempty"`
	State           State                `json:"state"`
	LastError       string               `json:"last_error,omitempty"`
	Metadata        map[string]string    `json:"metadata,omitempty"`
	Source          SourceSpec           `json:"source"`
	CreatedAt       time.Time            `json:"created_at"`
	UpdatedAt       time.Time            `json:"updated_at"`
	StartedAt       time.Time            `json:"started_at"`
	LastAlertTimes  map[string]time.Time `json:"last_alert_times,omitempty"`
	Notes           string               `json:"notes,omitempty"`
}

// NewRecord builds a ledger record with sane defaults.
func NewRecord(sampleID string, source SourceSpec) *Record {
	return &Record{
		ID:        newRecordID(),
		SampleID:  strings.TrimSpace(sampleID),
		Source:    source,
		State:     StateQueued,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
}

func newRecordID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("analysis-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

// Clone returns a deep copy of the record so the caller can mutate it safely.
func (r *Record) Clone() *Record {
	if r == nil {
		return nil
	}
	clone := *r
	if len(r.SampleArgs) > 0 {
		clone.SampleArgs = append([]string{}, r.SampleArgs...)
	}
	if len(r.Metadata) > 0 {
		clone.Metadata = make(map[string]string, len(r.Metadata))
		for k, v := range r.Metadata {
			clone.Metadata[k] = v
		}
	}
	if len(r.LastAlertTimes) > 0 {
		clone.LastAlertTimes = make(map[string]time.Time, len(r.LastAlertTimes))
		for k, v := range r.LastAlertTimes {
			clone.LastAlertTimes[k] = v
		}
	}
	return &clone
}

// ShouldStart reports if the orchestrator can attempt to start the analysis.
func (r *Record) ShouldStart() bool {
	return r != nil && r.State == StateQueued
}

// MarkStale updates the record so the orchestrator will terminate it.
func (r *Record) MarkStale() {
	if r == nil {
		return
	}
	switch r.State {
	case StateRunning:
		r.State = StateStale
	case StateQueued:
		r.State = StateStopped
	default:
		if r.State == StateStopped || r.State == StateStale || r.State == StateStopping {
			return
		}
		r.State = StateStale
	}
}

// ApplyState mutates the record and updates the modification timestamp.
func (r *Record) ApplyState(next State) {
	if r == nil || next == "" || r.State == next {
		return
	}
	r.State = next
	r.Touch()
}

// Touch refreshes the UpdatedAt timestamp.
func (r *Record) Touch() {
	if r == nil {
		return
	}
	r.UpdatedAt = time.Now().UTC()
}

// MatchesSampleConstraint enforces the "no duplicate sample/C2" rule.
func (r *Record) MatchesSampleConstraint(sampleID, c2 string) bool {
	if r == nil {
		return false
	}
	if r.SampleID != sampleID {
		return false
	}
	if c2 == "" || r.C2Address == "" {
		return true
	}
	return r.C2Address == c2
}

// RuntimeStatus mirrors the daemon status payload.
type RuntimeStatus struct {
	ID        string    `json:"id"`
	Sample    string    `json:"sample"`
	C2IP      string    `json:"c2_ip"`
	StartedAt time.Time `json:"started_at"`
	Running   bool      `json:"running"`
	Error     string    `json:"error,omitempty"`
}
