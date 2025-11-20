package analysis

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cochaviz/bottle/daemon"
)

// StartOptions mirror the daemon's StartAnalysisRequest while keeping the
// orchestration package decoupled from the transport details.
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
	return nil
}

func (o StartOptions) toDaemonRequest() daemon.StartAnalysisRequest {
	return daemon.StartAnalysisRequest{
		ID:              o.ID,
		SamplePath:      o.SamplePath,
		C2Address:       o.C2Address,
		ImageDir:        o.ImageDir,
		RunDir:          o.RunDir,
		ConnectionURI:   o.ConnectionURI,
		OverrideArch:    o.OverrideArch,
		SampleArgs:      append([]string{}, o.SampleArgs...),
		Instrumentation: o.Instrumentation,
		SampleTimeout:   o.SampleTimeout,
		SandboxLifetime: o.SandboxTimeout,
		LogLevel:        o.LogLevel,
	}
}

func generateDryRunID() string {
	return fmt.Sprintf("dry-%d", time.Now().UnixNano())
}
