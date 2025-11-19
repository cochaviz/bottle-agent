package analysis

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Runner defines the capabilities required to orchestrate analyses.
type Runner interface {
	Start(ctx context.Context, opts StartOptions) (string, error)
	Stop(ctx context.Context, id string) error
	List(ctx context.Context) ([]RuntimeStatus, error)
}

// StartOptions mirror the daemon's StartAnalysisRequest while keeping the
// orchestration package decoupled from any specific transport.
type StartOptions struct {
	ID              string
	SamplePath      string
	C2Address       string
	ImageDir        string
	RunDir          string
	ConnectionURI   string
	OverrideArch    string
	SampleArgs      []string
	Instrumentation string
	SampleTimeout   time.Duration
	SandboxTimeout  time.Duration
	LogLevel        string
}

// Validate ensures the options contain the bare minimum to launch an analysis.
func (o StartOptions) Validate() error {
	if strings.TrimSpace(o.SamplePath) == "" {
		return errors.New("sample_path is required")
	}
	if len(o.SampleArgs) == 0 {
		o.SampleArgs = nil
	}
	return nil
}

// DryRunner implements Runner but only records intent. It is used when a daemon
// connection is not configured so that the API remains usable for testing.
type DryRunner struct{}

// Start returns a fake ID while recording no state.
func (DryRunner) Start(ctx context.Context, opts StartOptions) (string, error) {
	if err := opts.Validate(); err != nil {
		return "", err
	}
	if opts.ID == "" {
		opts.ID = fmt.Sprintf("dry-%d", time.Now().UnixNano())
	}
	return opts.ID, nil
}

// Stop always succeeds since there is no actual process.
func (DryRunner) Stop(ctx context.Context, id string) error {
	return nil
}

// List returns an empty slice because nothing is running.
func (DryRunner) List(ctx context.Context) ([]RuntimeStatus, error) {
	return nil, nil
}
