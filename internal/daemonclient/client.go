package daemonclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"cochaviz/bottle-agent/internal/analysis"
)

const (
	commandStart = "start_analysis"
	commandStop  = "stop_analysis"
	commandList  = "list"
)

// Client implements the analysis.Runner interface by delegating to the bottle
// daemon via its unix socket IPC API.
type Client struct {
	socketPath  string
	logger      *slog.Logger
	dialTimeout time.Duration
}

// New constructs a daemon-backed runner.
func New(socketPath string, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	return &Client{
		socketPath:  socketPath,
		logger:      logger.With("component", "daemonclient"),
		dialTimeout: 10 * time.Second,
	}
}

// Start launches a new analysis via the daemon.
func (c *Client) Start(ctx context.Context, opts analysis.StartOptions) (string, error) {
	if strings.TrimSpace(c.socketPath) == "" {
		return "", errors.New("daemon socket path is empty")
	}
	if err := opts.Validate(); err != nil {
		return "", err
	}

	payload := startRequest{
		ID:              opts.ID,
		SamplePath:      opts.SamplePath,
		C2Address:       opts.C2Address,
		ImageDir:        opts.ImageDir,
		RunDir:          opts.RunDir,
		ConnectionURI:   opts.ConnectionURI,
		OverrideArch:    opts.OverrideArch,
		SampleArgs:      opts.SampleArgs,
		Instrumentation: opts.Instrumentation,
		SampleTimeout:   opts.SampleTimeout,
		SandboxLifetime: opts.SandboxTimeout,
		LogLevel:        opts.LogLevel,
	}
	resp, err := c.call(ctx, ipcRequest{Command: commandStart, Payload: payload})
	if err != nil {
		return "", err
	}
	var data struct {
		ID string `json:"id"`
	}
	if len(resp.Data) > 0 {
		if err := json.Unmarshal(resp.Data, &data); err != nil {
			return "", fmt.Errorf("decode start response: %w", err)
		}
	}
	if data.ID == "" {
		data.ID = opts.ID
	}
	return data.ID, nil
}

// Stop sends the stop command to the daemon.
func (c *Client) Stop(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return errors.New("analysis id is required")
	}
	_, err := c.call(ctx, ipcRequest{Command: commandStop, ID: id})
	return err
}

// List queries the daemon for active analyses.
func (c *Client) List(ctx context.Context) ([]analysis.RuntimeStatus, error) {
	resp, err := c.call(ctx, ipcRequest{Command: commandList})
	if err != nil {
		return nil, err
	}
	var statuses []analysis.RuntimeStatus
	if len(resp.Data) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(resp.Data, &statuses); err != nil {
		return nil, fmt.Errorf("decode list response: %w", err)
	}
	return statuses, nil
}

type ipcRequest struct {
	Command string      `json:"command"`
	ID      string      `json:"id,omitempty"`
	Payload interface{} `json:"payload,omitempty"`
}

type ipcResponse struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

type startRequest struct {
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

func (c *Client) call(ctx context.Context, req ipcRequest) (*ipcResponse, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}

	var resp ipcResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if !resp.OK {
		if resp.Error == "" {
			resp.Error = "daemon returned failure"
		}
		return nil, errors.New(resp.Error)
	}
	return &resp, nil
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	timeout := c.dialTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "unix", c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to daemon: %w", err)
	}
	return conn, nil
}
