package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	config "github.com/cochaviz/bottle/config"
)

type Command string

const (
	CommandStart Command = "start_analysis"
	CommandStop  Command = "stop_analysis"
	CommandList  Command = "list"
)

type IPCRequest struct {
	Command Command         `json:"command"`
	ID      string          `json:"id,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type IPCResponse struct {
	OK    bool        `json:"ok"`
	Error string      `json:"error,omitempty"`
	Data  interface{} `json:"data,omitempty"`
}

type StartAnalysisRequest struct {
	ID              string        `json:"id,omitempty"`
	SamplePath      string        `json:"sample_path"`
	C2Address       string        `json:"c2_address,omitempty"`
	ImageDir        string        `json:"image_dir,omitempty"`
	RunDir          string        `json:"run_dir,omitempty"`
	ConnectionURI   string        `json:"connection_uri,omitempty"`
	OverrideArch    string        `json:"override_arch,omitempty"`
	SampleArgs      []string      `json:"sample_args,omitempty"`
	Instrumentation string        `json:"instrumentation,omitempty"`
	SampleTimeout   time.Duration `json:"sample_timeout,omitempty"`
	SandboxLifetime time.Duration `json:"sandbox_lifetime,omitempty"`
	LogLevel        string        `json:"log_level,omitempty"`
}

type workerHandle struct {
	id      string
	opts    StartAnalysisRequest
	cancel  context.CancelFunc
	done    chan struct{}
	started time.Time
	err     error
}

type WorkerStatus struct {
	ID        string    `json:"id"`
	Sample    string    `json:"sample"`
	C2Ip      string    `json:"c2_ip"`
	StartedAt time.Time `json:"started_at"`
	Running   bool      `json:"running"`
	Error     string    `json:"error,omitempty"`
}

type Daemon struct {
	socketPath string
	logger     *slog.Logger

	mu      sync.Mutex
	workers map[string]*workerHandle

	listener net.Listener
	rootCtx  context.Context
	cancel   context.CancelFunc
}

func New(socketPath string, logger *slog.Logger) *Daemon {
	if logger == nil {
		logger = slog.Default()
	}
	return &Daemon{
		socketPath: socketPath,
		logger:     logger.With("component", "daemon"),
		workers:    make(map[string]*workerHandle),
	}
}

func (d *Daemon) Start(ctx context.Context) error {
	if d.listener != nil {
		return errors.New("daemon already started")
	}
	if d.socketPath == "" {
		return errors.New("socket path is required")
	}
	if err := os.Remove(d.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(d.socketPath), 0o755); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}
	l, err := net.Listen("unix", d.socketPath)
	if err != nil {
		return fmt.Errorf("listen on unix socket: %w", err)
	}
	if err := os.Chmod(d.socketPath, 0o660); err != nil {
		d.logger.Warn("failed to chmod socket", "error", err)
	}
	d.listener = l

	d.rootCtx, d.cancel = context.WithCancel(ctx)

	go func() {
		<-d.rootCtx.Done()
		_ = d.listener.Close()
		d.stopAll()
	}()

	d.logger.Info("daemon listening", "socket", d.socketPath)

	for {
		conn, err := d.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			select {
			case <-d.rootCtx.Done():
				return nil
			default:
			}
			d.logger.Warn("accept error", "error", err)
			continue
		}
		go d.handleConn(conn)
	}
}

func (d *Daemon) handleConn(conn net.Conn) {
	defer conn.Close()

	var req IPCRequest
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&req); err != nil {
		d.writeResponse(conn, IPCResponse{OK: false, Error: fmt.Sprintf("invalid request: %v", err)})
		return
	}

	switch req.Command {
	case CommandStart:
		d.handleStart(conn, req.Payload)
	case CommandStop:
		d.handleStop(conn, req.ID)
	case CommandList:
		d.handleList(conn)
	default:
		d.writeResponse(conn, IPCResponse{OK: false, Error: fmt.Sprintf("unknown command %q", req.Command)})
	}
}

func (d *Daemon) handleStart(conn net.Conn, payload json.RawMessage) {
	var startReq StartAnalysisRequest
	if err := json.Unmarshal(payload, &startReq); err != nil {
		d.writeResponse(conn, IPCResponse{OK: false, Error: fmt.Sprintf("decode payload: %v", err)})
		return
	}
	id, err := d.startAnalysis(startReq)
	if err != nil {
		d.writeResponse(conn, IPCResponse{OK: false, Error: err.Error()})
		return
	}
	d.writeResponse(conn, IPCResponse{OK: true, Data: map[string]string{"id": id}})
}

func (d *Daemon) handleStop(conn net.Conn, id string) {
	if id == "" {
		d.writeResponse(conn, IPCResponse{OK: false, Error: "id is required"})
		return
	}
	if err := d.stopAnalysis(id); err != nil {
		d.writeResponse(conn, IPCResponse{OK: false, Error: err.Error()})
		return
	}
	d.writeResponse(conn, IPCResponse{OK: true})
}

func (d *Daemon) handleList(conn net.Conn) {
	d.mu.Lock()
	defer d.mu.Unlock()

	statuses := make([]WorkerStatus, 0, len(d.workers))
	for _, handle := range d.workers {
		status := WorkerStatus{
			ID:        handle.id,
			Sample:    handle.opts.SamplePath,
			StartedAt: handle.started,
			C2Ip:      handle.opts.C2Address,
			Running:   true,
		}
		select {
		case <-handle.done:
			status.Running = false
			if handle.err != nil {
				status.Error = handle.err.Error()
			}
		default:
		}
		statuses = append(statuses, status)
	}

	d.writeResponse(conn, IPCResponse{OK: true, Data: statuses})
}

func (d *Daemon) writeResponse(conn net.Conn, resp IPCResponse) {
	encoder := json.NewEncoder(conn)
	_ = encoder.Encode(resp)
}

func (d *Daemon) startAnalysis(req StartAnalysisRequest) (string, error) {
	if d.rootCtx == nil {
		return "", errors.New("daemon not running")
	}
	if strings.TrimSpace(req.SamplePath) == "" {
		return "", errors.New("sample_path is required")
	}
	id := strings.TrimSpace(req.ID)
	if id == "" {
		id = uuid.New().String()
	}

	d.mu.Lock()
	if _, exists := d.workers[id]; exists {
		d.mu.Unlock()
		return "", fmt.Errorf("analysis with id %q already exists", id)
	}
	ctx, cancel := context.WithCancel(d.rootCtx)
	handle := &workerHandle{
		id:      id,
		opts:    req,
		cancel:  cancel,
		done:    make(chan struct{}),
		started: time.Now(),
	}
	d.workers[id] = handle
	d.mu.Unlock()

	logger := d.logger.With("analysis_id", id)

	go func() {
		defer close(handle.done)
		err := config.RunAnalysis(
			ctx,
			req.SamplePath,
			req.C2Address,
			req.ImageDir,
			req.RunDir,
			req.ConnectionURI,
			req.OverrideArch,
			req.SampleArgs,
			req.Instrumentation,
			req.SampleTimeout,
			req.SandboxLifetime,
			logger,
		)
		handle.err = err
		if err != nil {
			logger.Error("analysis failed", "error", err)
		}
		d.removeWorker(id, err)
	}()

	return id, nil
}

func (d *Daemon) stopAnalysis(id string) error {
	d.mu.Lock()
	handle, ok := d.workers[id]
	d.mu.Unlock()
	if !ok {
		return fmt.Errorf("analysis %q not found", id)
	}
	handle.cancel()
	select {
	case <-handle.done:
	case <-time.After(10 * time.Second):
		d.logger.Warn("timeout waiting for analysis to stop", "id", id)
	}
	return nil
}

func (d *Daemon) removeWorker(id string, err error) {
	d.mu.Lock()
	delete(d.workers, id)
	d.mu.Unlock()
	if err == nil {
		d.logger.Info("analysis completed", "id", id)
	}
}

func (d *Daemon) stopAll() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for id, handle := range d.workers {
		handle.cancel()
		select {
		case <-handle.done:
		case <-time.After(5 * time.Second):
			d.logger.Warn("timeout stopping analysis", "id", id)
		}
		delete(d.workers, id)
	}
}
