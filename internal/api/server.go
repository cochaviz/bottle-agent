package api

//go:generate sh -c "cd ../.. && go run github.com/swaggo/swag/cmd/swag@v1.16.6 init --generalInfo internal/api/server.go --dir . --output internal/api/docs --parseDependency --parseInternal"

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
	"sync"
	"time"

	"github.com/cochaviz/bottle-warden/internal/analysis"
	"github.com/cochaviz/bottle-warden/internal/api/docs"
	"github.com/cochaviz/bottle/daemon"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/go-chi/cors"
)

// @title bottle-warden API
// @version 1.0
// @description REST API for orchestrating bottle analyses and workers.
// @BasePath /

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
	openapiOnce  sync.Once
	openapiJSON  []byte
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
	router := s.buildRouter()

	srv := &http.Server{
		Addr:    s.addr,
		Handler: router,
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

func (s *Server) buildRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.StripSlashes)

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Allow-Failed"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
	}))

	r.Get("/health", s.handleHealth)
	r.Route("/analyses", func(r chi.Router) {
		r.Get("/", s.handleListAnalyses)
		r.Post("/", s.handleCreateAnalysis)
		r.Delete("/", s.handleDeleteAnalyses)
		r.Post("/batch", s.handleBatch)
		r.Route("/{id}", func(r chi.Router) {
			r.Put("/", s.updateAnalysisHandler)
			r.Delete("/", s.deleteAnalysisHandler)
		})
	})
	r.Route("/workers", func(r chi.Router) {
		r.Get("/", s.handleListWorkers)
		r.Get("/{id}", s.inspectWorkerHandler)
	})
	r.Get("/openapi.json", s.handleOpenAPI)

	return r
}

// handleHealth responds with a simple status indicator.
// @Summary Health check
// @Tags system
// @Produce json
// @Success 200 {object} HealthStatus
// @Router /health [get]
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.respondJSON(w, http.StatusOK, HealthStatus{Status: "ok"})
}

func (s *Server) updateAnalysisHandler(w http.ResponseWriter, r *http.Request) {
	s.handleUpdateAnalysis(w, r, chi.URLParam(r, "id"))
}

func (s *Server) deleteAnalysisHandler(w http.ResponseWriter, r *http.Request) {
	s.handleDeleteAnalysis(w, r, chi.URLParam(r, "id"))
}

func (s *Server) inspectWorkerHandler(w http.ResponseWriter, r *http.Request) {
	s.handleInspectWorker(w, r, chi.URLParam(r, "id"))
}

// @Summary Get OpenAPI document
// @Tags system
// @Produce json
// @Success 200 {object} any
// @Router /openapi.json [get]
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	s.openapiOnce.Do(func() {
		docs.SwaggerInfo.BasePath = "/"
		s.openapiJSON = []byte(docs.SwaggerInfo.ReadDoc())
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.openapiJSON)
}

// @Summary List analyses
// @Tags analyses
// @Produce json
// @Success 200 {array} analysis.Record
// @Router /analyses [get]
func (s *Server) handleListAnalyses(w http.ResponseWriter, r *http.Request) {
	records := s.ledger.List()
	s.respondJSON(w, http.StatusOK, records)
}

// @Summary List workers
// @Tags workers
// @Produce json
// @Success 200 {array} analysis.RuntimeStatus
// @Failure 503 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /workers [get]
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

// CreateAnalysisRequest represents the payload to add a single analysis.
type CreateAnalysisRequest struct {
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

// @Summary Create analysis
// @Tags analyses
// @Accept json
// @Produce json
// @Param request body CreateAnalysisRequest true "Analysis configuration"
// @Success 201 {object} analysis.Record
// @Failure 400 {object} ErrorResponse
// @Router /analyses [post]
func (s *Server) handleCreateAnalysis(w http.ResponseWriter, r *http.Request) {
	var req CreateAnalysisRequest
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

// UpdateAnalysisRequest carries partial fields for an existing analysis.
type UpdateAnalysisRequest struct {
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

// @Summary Update analysis
// @Tags analyses
// @Accept json
// @Produce json
// @Param id path string true "Analysis ID"
// @Param request body UpdateAnalysisRequest true "Fields to update"
// @Success 200 {object} analysis.Record
// @Failure 400 {object} ErrorResponse
// @Router /analyses/{id} [put]
func (s *Server) handleUpdateAnalysis(w http.ResponseWriter, r *http.Request, id string) {
	if strings.TrimSpace(id) == "" {
		s.respondError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	var req UpdateAnalysisRequest
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

// @Summary Delete analysis
// @Tags analyses
// @Param id path string true "Analysis ID"
// @Param X-Allow-Failed header bool false "Allow deletion of failed analyses"
// @Success 204
// @Failure 400 {object} ErrorResponse
// @Router /analyses/{id} [delete]
func (s *Server) handleDeleteAnalysis(w http.ResponseWriter, r *http.Request, id string) {
	if strings.TrimSpace(id) == "" {
		s.respondError(w, http.StatusBadRequest, errors.New("id is required"))
		return
	}
	allowFailed := strings.EqualFold(r.Header.Get("X-Allow-Failed"), "true")
	if err := s.ledger.Remove(id, allowFailed); err != nil {
		s.respondError(w, http.StatusBadRequest, err)
		return
	}
	s.bump()
	w.WriteHeader(http.StatusNoContent)
}

// @Summary Delete analyses by state
// @Tags analyses
// @Produce json
// @Param state query string true "State filter (only failed supported)" Enums(failed)
// @Success 200 {object} DeleteAnalysesResponse
// @Failure 400 {object} ErrorResponse
// @Router /analyses [delete]
func (s *Server) handleDeleteAnalyses(w http.ResponseWriter, r *http.Request) {
	stateParam := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("state")))
	if stateParam == "" {
		s.respondError(w, http.StatusBadRequest, errors.New("state query parameter is required"))
		return
	}
	if stateParam != string(analysis.StateFailed) {
		s.respondError(w, http.StatusBadRequest, fmt.Errorf("unsupported delete filter %q (only \"failed\" supported)", stateParam))
		return
	}
	deleted, err := s.ledger.RemoveByState(analysis.StateFailed)
	if err != nil {
		s.respondError(w, http.StatusBadRequest, err)
		return
	}
	s.bump()
	s.respondJSON(w, http.StatusOK, DeleteAnalysesResponse{
		Deleted: deleted,
		State:   stateParam,
	})
}

// BatchRequest is used to seed analyses from either a directory or hashes.
type BatchRequest struct {
	Directory       string            `json:"directory"`
	Hashes          []string          `json:"hashes"`
	Instrumentation string            `json:"instrumentation"`
	SampleTimeout   analysis.Duration `json:"sample_timeout"`
	SandboxTimeout  analysis.Duration `json:"sandbox_timeout"`
	Metadata        map[string]string `json:"metadata"`
}

// BatchResponse is returned when creating a batch of analyses.
type BatchResponse struct {
	BatchID  string             `json:"batch_id"`
	Count    int                `json:"count"`
	Analyses []*analysis.Record `json:"analyses"`
}

// DeleteAnalysesResponse represents the result of bulk delete.
type DeleteAnalysesResponse struct {
	Deleted int    `json:"deleted"`
	State   string `json:"state"`
}

// HealthStatus is returned by the health endpoint.
type HealthStatus struct {
	Status string `json:"status"`
}

// WorkerDetails is an alias to expose daemon worker details in docs.
type WorkerDetails = daemon.WorkerDetails

// @Summary Create analyses in batch
// @Tags analyses
// @Accept json
// @Produce json
// @Param request body BatchRequest true "Batch request payload"
// @Success 201 {object} BatchResponse
// @Failure 400 {object} ErrorResponse
// @Router /analyses/batch [post]
func (s *Server) handleBatch(w http.ResponseWriter, r *http.Request) {
	var req BatchRequest
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
		s.respondJSON(w, http.StatusCreated, BatchResponse{
			BatchID:  batchID,
			Count:    len(created),
			Analyses: created,
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
		s.respondJSON(w, http.StatusCreated, BatchResponse{
			BatchID:  batchID,
			Count:    len(created),
			Analyses: created,
		})
	}
}

// @Summary Inspect worker
// @Tags workers
// @Produce json
// @Param id path string true "Worker ID"
// @Success 200 {object} WorkerDetails
// @Failure 503 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /workers/{id} [get]
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

// ErrorResponse is the JSON shape for errors.
type ErrorResponse struct {
	Error string `json:"error"`
}

func (s *Server) respondError(w http.ResponseWriter, status int, err error) {
	s.logger.Warn("request failed", "status", status, "error", err)
	s.respondJSON(w, status, ErrorResponse{Error: err.Error()})
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
