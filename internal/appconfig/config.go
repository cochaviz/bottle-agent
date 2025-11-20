package appconfig

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration file definition.
type Config struct {
	Monitoring    MonitoringConfig    `yaml:"monitoring"`
	MalwareBazaar MalwareBazaarConfig `yaml:"malwarebazaar"`
}

// MonitoringConfig controls the eve.json watcher.
type MonitoringConfig struct {
	Enabled         bool          `yaml:"enabled"`
	EVEPath         string        `yaml:"eve_path"`
	CheckInterval   time.Duration `yaml:"check_interval"`
	DefaultTimeout  time.Duration `yaml:"default_timeout"`
	AnalysisTimeout time.Duration `yaml:"analysis_timeout"`
	Alerts          []AlertRule   `yaml:"alerts"`
}

// MalwareBazaarConfig controls integration with MalwareBazaar.
type MalwareBazaarConfig struct {
	Enabled   bool                       `yaml:"enabled"`
	APIKey    string                     `yaml:"api_key"`
	BaseURL   string                     `yaml:"base_url"`
	SampleDir string                     `yaml:"sample_dir"`
	Watcher   MalwareBazaarWatcherConfig `yaml:"watcher"`
}

type MalwareBazaarWatcherConfig struct {
	Enabled         bool          `yaml:"enabled"`
	WatchInterval   time.Duration `yaml:"watch_interval"`
	Instrumentation string        `yaml:"instrumentation"`
	SampleTimeout   time.Duration `yaml:"sample_timeout"`
	SandboxTimeout  time.Duration `yaml:"sandbox_timeout"`
	Tags            []string      `yaml:"tags"`
}

// AlertRule configures the inactivity timeout for a particular SID.
type AlertRule struct {
	SID     int           `yaml:"sid"`
	Timeout time.Duration `yaml:"timeout"`
}

// Load parses the YAML configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	cfg := &Config{
		Monitoring: MonitoringConfig{
			Enabled: true,
		},
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.Monitoring.normalize()
	cfg.MalwareBazaar.normalize()
	return cfg, nil
}

func (m *MonitoringConfig) normalize() {
	if m.CheckInterval <= 0 {
		m.CheckInterval = 30 * time.Second
	}
	if m.DefaultTimeout < 0 {
		m.DefaultTimeout = 0
	}
}

// Enabled reports whether monitoring is active.
func (m MonitoringConfig) Active() bool {
	if !m.Enabled {
		return false
	}
	if strings.TrimSpace(m.EVEPath) == "" {
		return false
	}
	if len(m.Alerts) == 0 && m.AnalysisTimeout <= 0 && m.DefaultTimeout <= 0 {
		return false
	}
	return true
}

func (m *MalwareBazaarConfig) normalize() {
	if strings.TrimSpace(m.SampleDir) == "" {
		m.SampleDir = "data/samples"
	}
	if strings.TrimSpace(m.BaseURL) == "" {
		m.BaseURL = "https://mb-api.abuse.ch/api/v1/"
	}
	m.Watcher.normalize()
}

func (w *MalwareBazaarWatcherConfig) normalize() {
	if w.WatchInterval <= 0 {
		w.WatchInterval = time.Hour
	}
	for i, tag := range w.Tags {
		w.Tags[i] = strings.ToLower(strings.TrimSpace(tag))
	}
}

// Active reports whether MalwareBazaar integration is configured.
func (m MalwareBazaarConfig) Active() bool {
	return m.Enabled
}

// TimeoutForSID resolves the timeout to use for the provided SID.
func (m MonitoringConfig) TimeoutForSID(sid int) time.Duration {
	for _, alert := range m.Alerts {
		if alert.SID == sid && alert.Timeout > 0 {
			return alert.Timeout
		}
	}
	return m.DefaultTimeout
}
