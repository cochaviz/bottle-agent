package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cochaviz/bottle-warden/internal/analysis"
)

// HashDownloader fetches samples from an external source using a hash.
type HashDownloader interface {
	FetchByHash(ctx context.Context, hash, destDir string) (string, error)
}

// Config drives the HTTP API server configuration.
type Config struct {
	ListenAddr   string
	Ledger       *analysis.Ledger
	Orchestrator *analysis.Orchestrator
	Logger       *slog.Logger
	Downloader   HashDownloader
	SampleDir    string
}

// Server exposes the REST API defined in the README.
type Server struct {
	addr         string
	ledger       *analysis.Ledger
	orchestrator *analysis.Orchestrator
	logger       *slog.Logger
	downloader   HashDownloader
	sampleDir    string
}

// NewServer instantiates the HTTP server.
func NewServer(cfg Config) (*Server, error) {
	if cfg.Ledger == nil {
		return nil, errors.New("ledger is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	addr := cfg.ListenAddr
	if addr == "" {
		addr = ":8080"
	}
	sampleDir := cfg.SampleDir
	if strings.TrimSpace(sampleDir) == "" {
		sampleDir = "data/samples"
	}
	if err := os.MkdirAll(sampleDir, 0o755); err != nil {
		return nil, fmt.Errorf("create sample dir: %w", err)
	}
	return &Server{
		addr:         addr,
		ledger:       cfg.Ledger,
		orchestrator: cfg.Orchestrator,
		logger:       logger.With("component", "api"),
		downloader:   cfg.Downloader,
		sampleDir:    sampleDir,
	}, nil
}

// Run starts the HTTP listener and blocks until the context is cancelled.
func (s *Server) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/analyses", s.handleAnalysesRoot)
	mux.HandleFunc("/analyses/", s.handleAnalysesSubpath)
	mux.HandleFunc("/workers", s.handleWorkersRoot)
	mux.HandleFunc("/workers/", s.handleWorkersSubpath)

	srv := &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	s.logger.Info("api listening", "address", s.addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleAnalysesRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/analyses" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.handleListAnalyses(w, r)
	case http.MethodPost:
		s.handleCreateAnalysis(w, r)
	default:
		s.methodNotAllowed(w, http.MethodGet, http.MethodPost)
	}
}

func (s *Server) handleAnalysesSubpath(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/analyses/")
	if path == "" {
		s.handleAnalysesRoot(w, r)
		return
	}
	if strings.Trim(path, "/") == "batch" {
		if r.Method != http.MethodPost {
			s.methodNotAllowed(w, http.MethodPost)
			return
		}
		s.handleBatch(w, r)
		return
	}
	chunks := strings.Split(strings.Trim(path, "/"), "/")
	if len(chunks) != 1 || chunks[0] == "" {
		http.NotFound(w, r)
		return
	}
	id := chunks[0]
	switch r.Method {
	case http.MethodPut:
		s.handleUpdateAnalysis(w, r, id)
	case http.MethodDelete:
		s.handleDeleteAnalysis(w, r, id)
	default:
		s.methodNotAllowed(w, http.MethodPut, http.MethodDelete)
	}
}

func (s *Server) handleWorkersRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/workers" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.handleListWorkers(w, r)
	default:
		s.methodNotAllowed(w, http.MethodGet)
	}
}

func (s *Server) handleWorkersSubpath(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/workers/")
	if path == "" {
		s.handleWorkersRoot(w, r)
		return
	}
	chunks := strings.Split(strings.Trim(path, "/"), "/")
	if len(chunks) != 1 || chunks[0] == "" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.handleInspectWorker(w, r, chunks[0])
	default:
		s.methodNotAllowed(w, http.MethodGet)
	}
}

func (s *Server) handleListAnalyses(w http.ResponseWriter, r *http.Request) {
	records := s.ledger.List()
	s.respondJSON(w, http.StatusOK, records)
}

func (s *Server) handleListWorkers(w http.ResponseWriter, r *http.Request) {
	if s.orchestrator == nil {
		s.respondError(w, http.StatusServiceUnavailable, errors.New("orchestrator is not configured"))
		return
	}
	statuses, err := s.orchestrator.ListRuntime(r.Context())
	if err != nil {
		statusCode := http.StatusInternalServerError
		if errors.Is(err, analysis.ErrDaemonUnavailable) {
			statusCode = http.StatusServiceUnavailable
		}
		s.respondError(w, statusCode, err)
		return
	}
	s.respondJSON(w, http.StatusOK, statuses)
}

type createRequest struct {
	SampleID        string               `json:"sample_id"`
	SamplePath      string               `json:"sample_path"`
	C2Address       string               `json:"c2_address"`
	Instrumentation string               `json:"instrumentation"`
	SampleArgs      []string             `json:"sample_args"`
	SampleTimeout   analysis.Duration    `json:"sample_timeout"`
	SandboxTimeout  analysis.Duration    `json:"sandbox_timeout"`
	BatchID         string               `json:"batch_id"`
	Metadata        map[string]string    `json:"metadata"`
	Notes           string               `json:"notes"`
	Source          *analysis.SourceSpec `json:"source"`
}

func (s *Server) handleCreateAnalysis(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, fmt.Errorf("decode request: %w", err))
		return
	}
	if strings.TrimSpace(req.SampleID) == "" {
		s.respondError(w, http.StatusBadRequest, errors.New("sample_id is required"))
		return
	}
	source := req.Source
	if source == nil {
		source = &analysis.SourceSpec{Type: analysis.SourceFile, Value: req.SamplePath}
	}
	if err := source.Validate(); err != nil {
		s.respondError(w, http.StatusBadRequest, err)
		return
	}
	record := analysis.NewRecord(req.SampleID, *source)
	record.SamplePath = req.SamplePath
	if record.SamplePath == "" && source.Type == analysis.SourceFile {
		record.SamplePath = source.Value
	}
	if source.Type == analysis.SourceHash {
		if s.downloader == nil {
			s.respondError(w, http.StatusBadRequest, errors.New("malwarebazaar integration is not configured"))
			return
		}
		path, err := s.downloader.FetchByHash(r.Context(), source.Value, s.sampleDir)
		if err != nil {
			s.respondError(w, http.StatusBadRequest, fmt.Errorf("fetch sample: %w", err))
			return
		}
		record.SamplePath = path
		if record.Metadata == nil {
			record.Metadata = make(map[string]string)
		}
		record.Metadata["source_hash"] = source.Value
	}
	record.C2Address = req.C2Address
	record.Instrumentation = req.Instrumentation
	record.SampleArgs = append([]string{}, req.SampleArgs...)
	record.SampleTimeout = req.SampleTimeout
	record.SandboxTimeout = req.SandboxTimeout
	record.BatchID = strings.TrimSpace(req.BatchID)
	record.Metadata = req.Metadata
	record.Notes = req.Notes

	created, err := s.ledger.Create(record)
	if err != nil {
		s.respondError(w, http.StatusBadRequest, err)
		return
	}
	s.bump()
	s.respondJSON(w, http.StatusCreated, created)
}

type updateRequest struct {
	SamplePath      *string            `json:"sample_path"`
	C2Address       *string            `json:"c2_address"`
	Instrumentation *string            `json:"instrumentation"`
	SampleArgs      *[]string          `json:"sample_args"`
	SampleTimeout   *analysis.Duration `json:"sample_timeout"`
	SandboxTimeout  *analysis.Duration `json:"sandbox_timeout"`
	State           *analysis.State    `json:"state"`
	Metadata        map[string]string  `json:"metadata"`
	Notes           *string            `json:"notes"`
}

func (s *Server) handleUpdateAnalysis(w http.ResponseWriter, r *http.Request, id string) {
	if strings.TrimSpace(id) == "" {
		s.respondError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	var req updateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, fmt.Errorf("decode request: %w", err))
		return
	}
	updated, err := s.ledger.Update(id, func(rec *analysis.Record) error {
		if req.SamplePath != nil {
			rec.SamplePath = *req.SamplePath
		}
		if req.C2Address != nil {
			rec.C2Address = *req.C2Address
		}
		if req.Instrumentation != nil {
			rec.Instrumentation = *req.Instrumentation
		}
		if req.SampleArgs != nil {
			rec.SampleArgs = append([]string{}, (*req.SampleArgs)...)
		}
		if req.SampleTimeout != nil {
			rec.SampleTimeout = *req.SampleTimeout
		}
		if req.SandboxTimeout != nil {
			rec.SandboxTimeout = *req.SandboxTimeout
		}
		if req.Metadata != nil {
			rec.Metadata = req.Metadata
		}
		if req.Notes != nil {
			rec.Notes = *req.Notes
		}
		if req.State != nil {
			switch *req.State {
			case analysis.StateQueued:
				rec.MarkRestart()
			case analysis.StateStale:
				rec.State = analysis.StateStale
			case analysis.StateStopped:
				rec.State = analysis.StateStopped
			default:
				return fmt.Errorf("unsupported state transition to %s", *req.State)
			}
		}
		return nil
	})
	if err != nil {
		s.respondError(w, http.StatusBadRequest, err)
		return
	}
	s.bump()
	s.respondJSON(w, http.StatusOK, updated)
}

func (s *Server) handleDeleteAnalysis(w http.ResponseWriter, r *http.Request, id string) {
	if strings.TrimSpace(id) == "" {
		s.respondError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	if err := s.ledger.Remove(id); err != nil {
		s.respondError(w, http.StatusBadRequest, err)
		return
	}
	s.bump()
	w.WriteHeader(http.StatusNoContent)
}

type batchRequest struct {
	Directory       string            `json:"directory"`
	Hashes          []string          `json:"hashes"`
	Instrumentation string            `json:"instrumentation"`
	SampleTimeout   analysis.Duration `json:"sample_timeout"`
	SandboxTimeout  analysis.Duration `json:"sandbox_timeout"`
	Metadata        map[string]string `json:"metadata"`
}

func (s *Server) handleBatch(w http.ResponseWriter, r *http.Request) {
	var req batchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, fmt.Errorf("decode request: %w", err))
		return
	}
	if strings.TrimSpace(req.Directory) == "" && len(req.Hashes) == 0 {
		s.respondError(w, http.StatusBadRequest, errors.New("directory or hashes is required"))
		return
	}
	if strings.TrimSpace(req.Directory) != "" {
		entries, err := os.ReadDir(req.Directory)
		if err != nil {
			s.respondError(w, http.StatusBadRequest, fmt.Errorf("read directory: %w", err))
			return
		}
		batchID := fmt.Sprintf("batch-%d", time.Now().UnixNano())
		var created []*analysis.Record
		position := 0
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			position++
			path := filepath.Join(req.Directory, entry.Name())
			sampleID := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
			if sampleID == "" {
				sampleID = entry.Name()
			}
			record := analysis.NewRecord(sampleID, analysis.SourceSpec{Type: analysis.SourceFile, Value: path})
			record.SamplePath = path
			record.Instrumentation = req.Instrumentation
			record.SampleTimeout = req.SampleTimeout
			record.SandboxTimeout = req.SandboxTimeout
			record.BatchID = batchID
			record.BatchPosition = position
			record.Metadata = req.Metadata
			rec, err := s.ledger.Create(record)
			if err != nil {
				s.respondError(w, http.StatusBadRequest, fmt.Errorf("create record for %s: %w", entry.Name(), err))
				return
			}
			created = append(created, rec)
		}
		s.bump()
		s.respondJSON(w, http.StatusCreated, map[string]any{
			"batch_id": batchID,
			"count":    len(created),
			"analyses": created,
		})
		return
	}
	if len(req.Hashes) > 0 {
		if s.downloader == nil {
			s.respondError(w, http.StatusBadRequest, errors.New("malwarebazaar integration is not configured"))
			return
		}
		batchID := fmt.Sprintf("batch-%d", time.Now().UnixNano())
		var created []*analysis.Record
		for idx, hash := range req.Hashes {
			hash = strings.TrimSpace(hash)
			if hash == "" {
				continue
			}
			path, err := s.downloader.FetchByHash(r.Context(), hash, s.sampleDir)
			if err != nil {
				s.respondError(w, http.StatusBadRequest, fmt.Errorf("fetch sample %s: %w", hash, err))
				return
			}
			record := analysis.NewRecord(hash, analysis.SourceSpec{Type: analysis.SourceHash, Value: hash})
			record.SamplePath = path
			record.BatchID = batchID
			record.BatchPosition = idx + 1
			record.Instrumentation = req.Instrumentation
			record.SampleTimeout = req.SampleTimeout
			record.SandboxTimeout = req.SandboxTimeout
			if record.Metadata == nil {
				record.Metadata = make(map[string]string)
			}
			for k, v := range req.Metadata {
				record.Metadata[k] = v
			}
			record.Metadata["source_hash"] = hash
			rec, err := s.ledger.Create(record)
			if err != nil {
				s.respondError(w, http.StatusBadRequest, fmt.Errorf("create record for hash %s: %w", hash, err))
				return
			}
			created = append(created, rec)
		}
		s.bump()
		s.respondJSON(w, http.StatusCreated, map[string]any{
			"batch_id": batchID,
			"count":    len(created),
			"analyses": created,
		})
	}
}

func (s *Server) handleInspectWorker(w http.ResponseWriter, r *http.Request, id string) {
	if s.orchestrator == nil {
		s.respondError(w, http.StatusServiceUnavailable, errors.New("orchestrator is not configured"))
		return
	}
	if strings.TrimSpace(id) == "" {
		s.respondError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	detail, err := s.orchestrator.InspectWorker(r.Context(), id)
	if err != nil {
		statusCode := http.StatusInternalServerError
		if errors.Is(err, analysis.ErrDaemonUnavailable) {
			statusCode = http.StatusServiceUnavailable
		}
		s.respondError(w, statusCode, err)
		return
	}
	s.respondJSON(w, http.StatusOK, detail)
}

func (s *Server) respondJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if payload != nil {
		_ = json.NewEncoder(w).Encode(payload)
	}
}

func (s *Server) respondError(w http.ResponseWriter, status int, err error) {
	s.logger.Warn("request failed", "status", status, "error", err)
	s.respondJSON(w, status, map[string]string{"error": err.Error()})
}

func (s *Server) bump() {
	if s.orchestrator != nil {
		s.orchestrator.Trigger()
	}
}

func (s *Server) methodNotAllowed(w http.ResponseWriter, allowed ...string) {
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}
