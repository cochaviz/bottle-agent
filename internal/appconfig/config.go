package appconfig

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the top-level configuration file definition.
type Config struct {
	Monitoring    MonitoringConfig
	MalwareBazaar MalwareBazaarConfig
}

// MonitoringConfig controls the eve.json watcher.
type MonitoringConfig struct {
	Enabled         bool
	EVEPath         string
	CheckInterval   time.Duration
	DefaultTimeout  time.Duration
	AnalysisTimeout time.Duration
	Alerts          []AlertRule
}

// MalwareBazaarConfig controls integration with MalwareBazaar.
type MalwareBazaarConfig struct {
	Enabled   bool
	APIKey    string
	BaseURL   string
	SampleDir string
	Watcher   MalwareBazaarWatcherConfig
}

type MalwareBazaarWatcherConfig struct {
	Enabled         bool
	WatchInterval   time.Duration
	Instrumentation string
	SampleTimeout   time.Duration
	SandboxTimeout  time.Duration
	Tags            []string
}

// AlertRule configures the inactivity timeout for a particular SID.
type AlertRule struct {
	SID     int
	Timeout time.Duration
}

// Load parses a YAML (limited subset) configuration file.
func Load(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer file.Close()

	cfg := &Config{}
	cfg.Monitoring.Enabled = true
	scanner := bufio.NewScanner(file)
	var (
		section           string
		sectionIndent     int
		inAlerts          bool
		alertIndent       int
		inWatcher         bool
		watcherIndent     int
		inWatcherTags     bool
		watcherTagsIndent int
		currentAlert      *AlertRule
		finalizeCurrent   = func() {
			if currentAlert == nil {
				return
			}
			if currentAlert.SID != 0 {
				cfg.Monitoring.Alerts = append(cfg.Monitoring.Alerts, *currentAlert)
			}
			currentAlert = nil
		}
	)

	for scanner.Scan() {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := countIndent(raw)

		if indent == 0 && strings.HasSuffix(trimmed, ":") {
			finalizeCurrent()
			section = strings.TrimSuffix(trimmed, ":")
			sectionIndent = indent
			inAlerts = false
			continue
		}

		if section != "monitoring" {
			if section == "malwarebazaar" {
				if strings.HasSuffix(trimmed, ":") && indent > sectionIndent {
					key := strings.TrimSuffix(trimmed, ":")
					if key == "watcher" {
						inWatcher = true
						watcherIndent = indent
						continue
					}
				}
				if inWatcher {
					if indent <= watcherIndent {
						inWatcher = false
						inWatcherTags = false
					} else {
						if strings.HasSuffix(trimmed, ":") && indent > watcherIndent {
							key := strings.TrimSuffix(trimmed, ":")
							if key == "tags" {
								inWatcherTags = true
								watcherTagsIndent = indent
								cfg.MalwareBazaar.Watcher.Tags = nil
								continue
							}
						}
						if inWatcherTags {
							if indent <= watcherTagsIndent {
								inWatcherTags = false
							} else if strings.HasPrefix(trimmed, "- ") {
								tag := strings.ToLower(strings.TrimSpace(trimmed[2:]))
								if tag != "" {
									cfg.MalwareBazaar.Watcher.Tags = append(cfg.MalwareBazaar.Watcher.Tags, tag)
								}
								continue
							}
						}
						if err := assignMalwareWatcherField(&cfg.MalwareBazaar.Watcher, trimmed); err != nil {
							return nil, err
						}
						continue
					}
				}
				if err := assignMalwareBazaarField(&cfg.MalwareBazaar, trimmed); err != nil {
					return nil, err
				}
			}
			continue
		}

		if strings.HasSuffix(trimmed, ":") && indent > sectionIndent {
			key := strings.TrimSuffix(trimmed, ":")
			if key == "alerts" {
				finalizeCurrent()
				inAlerts = true
				alertIndent = indent
				continue
			}
		}

		if inAlerts {
			if indent <= alertIndent {
				finalizeCurrent()
				inAlerts = false
			} else {
				if strings.HasPrefix(trimmed, "- ") && currentAlert != nil {
					finalizeCurrent()
				}
				if err := parseAlertLine(trimmed, &currentAlert); err != nil {
					return nil, err
				}
				continue
			}
		}

		if err := assignMonitoringField(&cfg.Monitoring, trimmed); err != nil {
			return nil, err
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	finalizeCurrent()
	cfg.Monitoring.normalize()
	cfg.MalwareBazaar.normalize()
	return cfg, nil
}

func assignMonitoringField(m *MonitoringConfig, line string) error {
	key, value, ok := splitKeyValue(line)
	if !ok {
		return fmt.Errorf("invalid monitoring line: %q", line)
	}
	switch key {
	case "enabled":
		if value == "" {
			return errors.New("enabled requires a value")
		}
		val := strings.ToLower(value)
		m.Enabled = !(val == "false" || val == "0" || val == "no")
	case "eve_path":
		m.EVEPath = value
	case "check_interval":
		dur, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("parse check_interval: %w", err)
		}
		m.CheckInterval = dur
	case "default_timeout":
		dur, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("parse default_timeout: %w", err)
		}
		m.DefaultTimeout = dur
	case "analysis_timeout":
		dur, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("parse analysis_timeout: %w", err)
		}
		m.AnalysisTimeout = dur
	default:
		// ignore unknown keys so the config can evolve.
	}
	return nil
}

func assignMalwareBazaarField(m *MalwareBazaarConfig, line string) error {
	key, value, ok := splitKeyValue(line)
	if !ok {
		return fmt.Errorf("invalid malwarebazaar line: %q", line)
	}
	switch key {
	case "enabled":
		val := strings.ToLower(value)
		m.Enabled = !(val == "false" || val == "0" || val == "no")
	case "api_key":
		m.APIKey = value
	case "base_url":
		m.BaseURL = value
	case "sample_dir":
		m.SampleDir = value
	case "watch":
		val := strings.ToLower(value)
		m.Watcher.Enabled = !(val == "false" || val == "0" || val == "no")
	case "instrumentation":
		m.Watcher.Instrumentation = value
	case "sample_timeout":
		dur, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("parse sample_timeout: %w", err)
		}
		m.Watcher.SampleTimeout = dur
	case "sandbox_timeout":
		dur, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("parse sandbox_timeout: %w", err)
		}
		m.Watcher.SandboxTimeout = dur
	case "tags":
		if value == "" {
			m.Watcher.Tags = nil
			return nil
		}
		parts := strings.Split(value, ",")
		for _, part := range parts {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				m.Watcher.Tags = append(m.Watcher.Tags, strings.ToLower(trimmed))
			}
		}
	default:
	}
	return nil
}

func assignMalwareWatcherField(w *MalwareBazaarWatcherConfig, line string) error {
	key, value, ok := splitKeyValue(line)
	if !ok {
		return fmt.Errorf("invalid malwarebazaar watcher line: %q", line)
	}
	switch key {
	case "enabled":
		val := strings.ToLower(value)
		w.Enabled = !(val == "false" || val == "0" || val == "no")
	case "watch_interval":
		dur, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("parse watch_interval: %w", err)
		}
		w.WatchInterval = dur
	case "instrumentation":
		w.Instrumentation = value
	case "sample_timeout":
		dur, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("parse watcher sample_timeout: %w", err)
		}
		w.SampleTimeout = dur
	case "sandbox_timeout":
		dur, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("parse watcher sandbox_timeout: %w", err)
		}
		w.SandboxTimeout = dur
	case "tags":
		if value == "" {
			w.Tags = nil
			return nil
		}
		parts := strings.Split(value, ",")
		for _, part := range parts {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				w.Tags = append(w.Tags, strings.ToLower(trimmed))
			}
		}
	default:
	}
	return nil
}

func parseAlertLine(line string, current **AlertRule) error {
	newEntry := false
	if strings.HasPrefix(line, "- ") {
		line = strings.TrimSpace(line[2:])
		newEntry = true
	}
	if *current == nil || newEntry {
		*current = &AlertRule{}
	}
	if line == "" {
		return nil
	}
	key, value, ok := splitKeyValue(line)
	if !ok {
		return fmt.Errorf("invalid alert line: %q", line)
	}
	switch key {
	case "sid":
		id, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("parse sid %q: %w", value, err)
		}
		(*current).SID = id
	case "timeout":
		dur, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("parse alert timeout: %w", err)
		}
		(*current).Timeout = dur
	default:
		return fmt.Errorf("unknown alert key %q", key)
	}
	return nil
}

func splitKeyValue(line string) (string, string, bool) {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return "", "", false
	}
	key := strings.TrimSpace(line[:idx])
	value := strings.TrimSpace(line[idx+1:])
	value = strings.Trim(value, `"'`)
	return key, value, true
}

func countIndent(line string) int {
	count := 0
	for _, r := range line {
		if r == ' ' {
			count++
			continue
		}
		break
	}
	return count
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
