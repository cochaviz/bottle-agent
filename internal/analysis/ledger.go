package analysis

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Ledger persists analysis records in a JSON Lines file. The file is designed
// to be human-readable/editable while still supporting atomic updates.
type Ledger struct {
	path     string
	logger   *slog.Logger
	mu       sync.RWMutex
	entries  map[string]*Record
	order    []string
	modTime  time.Time
	fileSize int64
}

// NewLedger opens (or creates) a ledger bound to the provided path.
func NewLedger(path string, logger *slog.Logger) (*Ledger, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("ledger path is required")
	}
	l := &Ledger{
		path:    path,
		logger:  logger,
		entries: make(map[string]*Record),
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create ledger directory: %w", err)
	}
	if err := l.loadLocked(); err != nil {
		return nil, err
	}
	return l, nil
}

// Path exposes the underlying path, mostly useful for introspection.
func (l *Ledger) Path() string {
	return l.path
}

// Reload pulls the latest state from disk if the file has changed since the
// previous load.
func (l *Ledger) Reload() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	info, err := os.Stat(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			if len(l.entries) == 0 {
				return nil
			}
			l.entries = make(map[string]*Record)
			l.order = nil
			l.modTime = time.Time{}
			l.fileSize = 0
			return nil
		}
		return err
	}
	if info.ModTime().Equal(l.modTime) && info.Size() == l.fileSize {
		return nil
	}
	return l.loadLocked()
}

// List returns clones of the known records ordered by insertion time.
func (l *Ledger) List() []*Record {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]*Record, 0, len(l.order))
	for _, id := range l.order {
		if rec, ok := l.entries[id]; ok {
			out = append(out, rec.Clone())
		}
	}
	return out
}

// Get looks up a record by id.
func (l *Ledger) Get(id string) (*Record, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	rec, ok := l.entries[id]
	if !ok {
		return nil, false
	}
	return rec.Clone(), true
}

// Create persists a new record after ensuring constraints are satisfied.
func (l *Ledger) Create(rec *Record) (*Record, error) {
	if rec == nil {
		return nil, errors.New("record is required")
	}
	if err := rec.Source.Validate(); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if rec.ID == "" {
		rec.ID = fmt.Sprintf("analysis-%d", time.Now().UnixNano())
	}
	rec.CreatedAt = time.Now().UTC()
	rec.UpdatedAt = rec.CreatedAt
	if _, exists := l.entries[rec.ID]; exists {
		return nil, fmt.Errorf("analysis %q already exists", rec.ID)
	}
	if err := l.enforceSampleConstraintsLocked(rec); err != nil {
		return nil, err
	}
	l.entries[rec.ID] = rec.Clone()
	l.order = append(l.order, rec.ID)
	if err := l.persistLocked(); err != nil {
		delete(l.entries, rec.ID)
		l.order = slices.DeleteFunc(l.order, func(id string) bool { return id == rec.ID })
		return nil, err
	}
	return rec.Clone(), nil
}

// Update applies a mutation callback with the ledger locked.
func (l *Ledger) Update(id string, mutate func(*Record) error) (*Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, ok := l.entries[id]
	if !ok {
		return nil, fmt.Errorf("analysis %q not found", id)
	}
	clone := rec.Clone()
	if err := mutate(clone); err != nil {
		return nil, err
	}
	if err := l.enforceSampleConstraintsLocked(clone); err != nil {
		return nil, err
	}
	clone.Touch()
	l.entries[id] = clone
	if err := l.persistLocked(); err != nil {
		return nil, err
	}
	return clone.Clone(), nil
}

// Remove deletes a record once it is no longer active.
func (l *Ledger) Remove(id string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, ok := l.entries[id]
	if !ok {
		return fmt.Errorf("analysis %q not found", id)
	}
	if rec.State.Active() || rec.State == StateStale || rec.State == StateStopping {
		return fmt.Errorf("analysis %s is still active (%s)", id, rec.State)
	}
	delete(l.entries, id)
	l.order = slices.DeleteFunc(l.order, func(entryID string) bool { return entryID == id })
	return l.persistLocked()
}

// HasBatchPredecessor indicates whether another record from the same batch
// needs to finish before this one can start.
func (l *Ledger) HasBatchPredecessor(id string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	rec, ok := l.entries[id]
	if !ok || rec.BatchID == "" {
		return false
	}
	for _, otherID := range l.order {
		if otherID == id {
			break
		}
		other := l.entries[otherID]
		if other.BatchID != rec.BatchID {
			continue
		}
		if other.State.Active() || other.State == StateQueued {
			return true
		}
		if other.State == StateStale || other.State == StateStopping {
			return true
		}
	}
	return false
}

// loadLocked loads the ledger file with the mutex already held.
func (l *Ledger) loadLocked() error {
	file, err := os.OpenFile(l.path, os.O_RDONLY|os.O_CREATE, 0o644)
	if err != nil {
		return fmt.Errorf("open ledger: %w", err)
	}
	defer file.Close()

	entries := make(map[string]*Record)
	order := make([]string, 0)
	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var rec Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return fmt.Errorf("decode ledger line %d: %w", lineNum, err)
		}
		if rec.ID == "" {
			rec.ID = fmt.Sprintf("analysis-%d", time.Now().UnixNano())
		}
		if rec.CreatedAt.IsZero() {
			rec.CreatedAt = time.Now().UTC()
		}
		if rec.UpdatedAt.IsZero() {
			rec.UpdatedAt = rec.CreatedAt
		}
		entries[rec.ID] = rec.Clone()
		order = append(order, rec.ID)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read ledger: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat ledger: %w", err)
	}
	l.entries = entries
	l.order = order
	l.modTime = info.ModTime()
	l.fileSize = info.Size()
	return nil
}

func (l *Ledger) persistLocked() error {
	tmp, err := os.CreateTemp(filepath.Dir(l.path), "ledger-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp ledger: %w", err)
	}
	encoder := json.NewEncoder(tmp)
	for _, id := range l.order {
		rec, ok := l.entries[id]
		if !ok {
			continue
		}
		if err := encoder.Encode(rec); err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return fmt.Errorf("encode ledger record %s: %w", id, err)
		}
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("flush ledger: %w", err)
	}
	if err := os.Rename(tmp.Name(), l.path); err != nil {
		os.Remove(tmp.Name())
		return fmt.Errorf("replace ledger: %w", err)
	}
	info, err := os.Stat(l.path)
	if err != nil {
		return fmt.Errorf("stat ledger: %w", err)
	}
	l.modTime = info.ModTime()
	l.fileSize = info.Size()
	return nil
}

func (l *Ledger) enforceSampleConstraintsLocked(candidate *Record) error {
	if candidate == nil {
		return errors.New("record is required")
	}
	if strings.TrimSpace(candidate.SampleID) == "" {
		return errors.New("sample_id is required")
	}
	for id, rec := range l.entries {
		if id == candidate.ID {
			continue
		}
		if !rec.MatchesSampleConstraint(candidate.SampleID, candidate.C2Address) {
			continue
		}
		if rec.State.Active() || candidate.State.Active() {
			return fmt.Errorf("sample %s already active in analysis %s", candidate.SampleID, id)
		}
		if rec.C2Address == candidate.C2Address && candidate.C2Address != "" && !rec.State.Terminal() {
			return fmt.Errorf("analysis for sample %s and c2 %s already exists (%s)", candidate.SampleID, candidate.C2Address, id)
		}
		if rec.C2Address == "" || candidate.C2Address == "" {
			if !rec.State.Terminal() {
				return fmt.Errorf("analysis for sample %s already exists (%s)", candidate.SampleID, id)
			}
		}
	}
	return nil
}
