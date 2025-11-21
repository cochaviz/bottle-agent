package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/cochaviz/bottle-warden/internal/analysis"
)

func TestHandleUpdateAnalysisRestartResetsState(t *testing.T) {
	t.Helper()
	srv := newTestServer(t)

	rec := analysis.NewRecord("sample-restart", analysis.SourceSpec{Type: analysis.SourceFile, Value: "dummy"})
	rec.SamplePath = "dummy"
	rec.State = analysis.StateStale
	rec.StartedAt = time.Now()
	rec.LastError = "stale"
	rec.LastAlertTimes = map[string]time.Time{"200001": time.Now()}
	rec.Metadata = map[string]string{"stale_reason": "sid 200001 inactive"}

	created, err := srv.ledger.Create(rec)
	if err != nil {
		t.Fatalf("create record: %v", err)
	}

	body := map[string]string{"state": string(analysis.StateQueued)}
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/analyses/"+created.ID, bytes.NewReader(payload))
	w := httptest.NewRecorder()

	srv.handleUpdateAnalysis(w, req, created.ID)
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	updated, ok := srv.ledger.Get(created.ID)
	if !ok {
		t.Fatalf("updated record not found")
	}
	if updated.State != analysis.StateQueued {
		t.Fatalf("expected state queued, got %s", updated.State)
	}
	if !updated.StartedAt.IsZero() {
		t.Fatalf("expected StartedAt cleared, got %s", updated.StartedAt)
	}
	if updated.LastError != "" {
		t.Fatalf("expected LastError cleared, got %q", updated.LastError)
	}
	if updated.LastAlertTimes != nil {
		t.Fatalf("expected LastAlertTimes cleared, got %v", updated.LastAlertTimes)
	}
	if _, exists := updated.Metadata["stale_reason"]; exists {
		t.Fatalf("expected stale_reason removed, metadata=%v", updated.Metadata)
	}
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	ledgerPath := filepath.Join(t.TempDir(), "ledger.jsonl")
	ledger, err := analysis.NewLedger(ledgerPath, nil)
	if err != nil {
		t.Fatalf("new ledger: %v", err)
	}
	srv, err := NewServer(Config{
		Ledger:    ledger,
		SampleDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return srv
}
