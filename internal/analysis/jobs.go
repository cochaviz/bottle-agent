package analysis

import (
	"errors"
	"fmt"
	"path/filepath"
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

func (o StartOptions) toDaemonRequest() (daemon.StartAnalysisRequest, error) {
	samplePath, err := absolutePath(o.SamplePath)
	if err != nil {
		return daemon.StartAnalysisRequest{}, fmt.Errorf("resolve sample path: %w", err)
	}
	imageDir, err := absolutePath(o.ImageDir)
	if err != nil {
		return daemon.StartAnalysisRequest{}, fmt.Errorf("resolve image dir: %w", err)
	}
	runDir, err := absolutePath(o.RunDir)
	if err != nil {
		return daemon.StartAnalysisRequest{}, fmt.Errorf("resolve run dir: %w", err)
	}
	return daemon.StartAnalysisRequest{
		ID:              o.ID,
		SamplePath:      samplePath,
		C2Address:       o.C2Address,
		ImageDir:        imageDir,
		RunDir:          runDir,
		ConnectionURI:   o.ConnectionURI,
		OverrideArch:    o.OverrideArch,
		SampleArgs:      append([]string{}, o.SampleArgs...),
		Instrumentation: o.Instrumentation,
		SampleTimeout:   o.SampleTimeout,
		SandboxLifetime: o.SandboxTimeout,
		LogLevel:        o.LogLevel,
	}, nil
}

func generateDryRunID() string {
	return fmt.Sprintf("dry-%d", time.Now().UnixNano())
}

func absolutePath(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	return abs, nil
}
