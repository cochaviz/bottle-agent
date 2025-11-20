package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/cochaviz/bottle-warden/internal/analysis"
	"github.com/cochaviz/bottle-warden/internal/api"
	"github.com/cochaviz/bottle-warden/internal/appconfig"
	"github.com/cochaviz/bottle-warden/internal/daemonclient"
	"github.com/cochaviz/bottle-warden/internal/malwarebazaar"
	"github.com/spf13/cobra"
)

var (
	logLevelFlag string

	serveListen       string
	serveLedgerPath   string
	serveDaemonSocket string
	servePollInterval time.Duration
	serveConfigPath   string

	clientServerURL              string
	clientAddSampleID            string
	clientAddSamplePath          string
	clientAddSourceHash          string
	clientAddC2Address           string
	clientAddInstrumentation     string
	clientAddBulkDir             string
	clientAddBulkHashes          string
	clientAddBulkInstrumentation string
)

var rootCmd = &cobra.Command{
	Use:   "bottle-warden",
	Short: "bottle-warden orchestration and monitoring tooling",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		level, err := parseLogLevel(logLevelFlag)
		if err != nil {
			return err
		}
		rootLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

var rootLogger *slog.Logger

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "run the bottle-warden orchestrator, server, and monitoring stack",
	RunE: func(cmd *cobra.Command, args []string) error {
		runServer(rootLogger, serveListen, serveLedgerPath, serveDaemonSocket, servePollInterval, serveConfigPath)
		return nil
	},
}

var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "interact with the running bottle-warden service",
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

var clientStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "list analyses in the agent ledger",
	RunE: func(cmd *cobra.Command, args []string) error {
		return clientStatus(clientServerURL)
	},
}

var clientDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "remove an analysis",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return clientDelete(clientServerURL, args[0])
	},
}

var clientAddCmd = &cobra.Command{
	Use:   "add",
	Short: "enqueue a single analysis",
	RunE: func(cmd *cobra.Command, args []string) error {
		return clientAdd(clientServerURL, clientAddSampleID, clientAddSamplePath, clientAddSourceHash, clientAddC2Address, clientAddInstrumentation)
	},
}

var clientAddBulkCmd = &cobra.Command{
	Use:   "add-bulk",
	Short: "enqueue multiple analyses from a directory or hash list",
	RunE: func(cmd *cobra.Command, args []string) error {
		return clientAddBulk(clientServerURL, clientAddBulkDir, clientAddBulkHashes, clientAddBulkInstrumentation)
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&logLevelFlag, "log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.AddCommand(serveCmd, clientCmd)

	serveCmd.Flags().StringVar(&serveListen, "listen", ":8080", "HTTP listen address")
	serveCmd.Flags().StringVar(&serveLedgerPath, "ledger", "data/ledger.jsonl", "ledger file path")
	serveCmd.Flags().StringVar(&serveDaemonSocket, "daemon-socket", "/var/run/bottle/daemon.sock", "path to the bottle daemon unix socket")
	serveCmd.Flags().DurationVar(&servePollInterval, "poll", 5*time.Second, "orchestrator poll interval")
	serveCmd.Flags().StringVar(&serveConfigPath, "config", "", "path to YAML configuration file")

	clientCmd.PersistentFlags().StringVar(&clientServerURL, "server", "http://127.0.0.1:8080", "bottle-warden API base URL")
	clientCmd.AddCommand(clientStatusCmd, clientDeleteCmd, clientAddCmd, clientAddBulkCmd)

	clientAddCmd.Flags().StringVar(&clientAddSampleID, "sample", "", "sample identifier (required)")
	clientAddCmd.Flags().StringVar(&clientAddSamplePath, "path", "", "local sample path")
	clientAddCmd.Flags().StringVar(&clientAddSourceHash, "hash", "", "MalwareBazaar hash to fetch")
	clientAddCmd.Flags().StringVar(&clientAddC2Address, "c2", "", "C2 address")
	clientAddCmd.Flags().StringVar(&clientAddInstrumentation, "instrumentation", "", "instrumentation profile")
	_ = clientAddCmd.MarkFlagRequired("sample")

	clientAddBulkCmd.Flags().StringVar(&clientAddBulkDir, "dir", "", "directory of samples")
	clientAddBulkCmd.Flags().StringVar(&clientAddBulkHashes, "hashes", "", "comma-separated hashes")
	clientAddBulkCmd.Flags().StringVar(&clientAddBulkInstrumentation, "instrumentation", "", "instrumentation profile")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runServer(logger *slog.Logger, listenAddr, ledgerPath, daemonSocket string, pollInterval time.Duration, configPath string) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ledger, err := analysis.NewLedger(ledgerPath, logger)
	if err != nil {
		logger.Error("failed to load ledger", "error", err)
		os.Exit(1)
	}

	var fileConfig *appconfig.Config
	if strings.TrimSpace(configPath) != "" {
		cfg, err := appconfig.Load(configPath)
		if err != nil {
			logger.Error("failed to load config", "error", err)
			os.Exit(1)
		}
		fileConfig = cfg
		if cfg.Monitoring.EVEPath != "" {
			logger.Info("loaded monitoring config", "eve_path", cfg.Monitoring.EVEPath)
		}
	}
	var monitoringCfg appconfig.MonitoringConfig
	var bazaarCfg appconfig.MalwareBazaarConfig
	if fileConfig != nil {
		monitoringCfg = fileConfig.Monitoring
		bazaarCfg = fileConfig.MalwareBazaar
	}

	sampleDir := bazaarCfg.SampleDir
	if strings.TrimSpace(sampleDir) == "" {
		sampleDir = "data/samples"
	}
	if err := os.MkdirAll(sampleDir, 0o755); err != nil {
		logger.Error("failed to prepare sample directory", "dir", sampleDir, "error", err)
		os.Exit(1)
	}

	var runner analysis.Runner
	if strings.TrimSpace(daemonSocket) != "" {
		runner = daemonclient.New(daemonSocket, logger)
	} else {
		runner = analysis.DryRunner{}
		logger.Warn("daemon socket not configured, falling back to dry-run runner")
	}

	orchestrator := analysis.NewOrchestrator(ledger, runner, analysis.OrchestratorConfig{
		PollInterval: pollInterval,
		Logger:       logger,
	})

	var downloader *malwarebazaar.Client
	envAPIKey := strings.TrimSpace(os.Getenv("MALWAREBAZAAR_API_KEY"))
	if strings.TrimSpace(bazaarCfg.APIKey) != "" {
		envAPIKey = bazaarCfg.APIKey
	}
	if bazaarCfg.Enabled || envAPIKey != "" {
		baseURL := bazaarCfg.BaseURL
		if strings.TrimSpace(baseURL) == "" {
			baseURL = malwarebazaar.DefaultBaseURL
		}
		downloader = &malwarebazaar.Client{
			BaseURL: baseURL,
			APIKey:  envAPIKey,
			Logger:  logger,
		}
	}

	server, err := api.NewServer(api.Config{
		ListenAddr:   listenAddr,
		Ledger:       ledger,
		Orchestrator: orchestrator,
		Logger:       logger,
		Downloader:   downloader,
		SampleDir:    sampleDir,
	})
	if err != nil {
		logger.Error("failed to create API server", "error", err)
		os.Exit(1)
	}

	monitor := analysis.NewMonitor(ledger, orchestrator, monitoringCfg, logger)

	var bazaarWatcher *malwarebazaar.Watcher
	if downloader != nil && bazaarCfg.Enabled && bazaarCfg.Watcher.Enabled {
		bazaarWatcher = malwarebazaar.NewWatcher(downloader, ledger, orchestrator, bazaarCfg.Watcher, sampleDir, logger)
	}

	errCh := make(chan error, 4)

	go func() {
		if err := orchestrator.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- err
		}
	}()

	go func() {
		if err := server.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- err
		}
	}()

	go func() {
		if err := monitor.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- err
		}
	}()

	if bazaarWatcher != nil {
		go func() {
			if err := bazaarWatcher.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				errCh <- err
			}
		}()
	}

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil {
			logger.Error("component failed", "error", err)
			os.Exit(1)
		}
	}
}

func parseLogLevel(level string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown log level %q", level)
	}
}

func clientStatus(baseURL string) error {
	resp, err := http.Get(strings.TrimRight(baseURL, "/") + "/analyses")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status request failed: %s", strings.TrimSpace(string(body)))
	}
	var records []*analysis.Record
	if err := json.NewDecoder(resp.Body).Decode(&records); err != nil {
		return err
	}
	if len(records) == 0 {
		fmt.Println("No analyses found.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSAMPLE\tSTATE\tC2\tSTARTED\tUPDATED\tLAST ERROR")
	for _, rec := range records {
		start := "-"
		if !rec.StartedAt.IsZero() {
			start = rec.StartedAt.Format(time.RFC3339)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			rec.ID, rec.SampleID, rec.State, rec.C2Address, start, rec.UpdatedAt.Format(time.RFC3339), rec.LastError)
	}
	w.Flush()
	return nil
}

func clientDelete(baseURL, id string) error {
	req, err := http.NewRequest(http.MethodDelete, strings.TrimRight(baseURL, "/")+"/analyses/"+id, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete failed: %s", strings.TrimSpace(string(body)))
	}
	fmt.Println("Deleted", id)
	return nil
}

func clientAdd(baseURL, sampleID, samplePath, sourceHash, c2, instrumentation string) error {
	if strings.TrimSpace(sampleID) == "" {
		return errors.New("sample is required")
	}
	body := map[string]interface{}{
		"sample_id":       sampleID,
		"sample_path":     samplePath,
		"c2_address":      c2,
		"instrumentation": instrumentation,
		"sample_args":     []string{},
		"metadata":        map[string]string{},
		"notes":           "",
	}
	if strings.TrimSpace(sourceHash) != "" {
		body["source"] = map[string]string{"type": "hash", "value": sourceHash}
	} else if strings.TrimSpace(samplePath) != "" {
		body["source"] = map[string]string{"type": "file", "value": samplePath}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := http.Post(strings.TrimRight(baseURL, "/")+"/analyses", "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("add failed: %s", strings.TrimSpace(string(respBody)))
	}
	var created analysis.Record
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return err
	}
	fmt.Println("Created analysis", created.ID)
	return nil
}

func clientAddBulk(baseURL, dir, hashes, instrumentation string) error {
	req := map[string]interface{}{
		"directory":       dir,
		"hashes":          []string{},
		"instrumentation": instrumentation,
	}
	if strings.TrimSpace(hashes) != "" {
		parts := strings.Split(hashes, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		req["hashes"] = parts
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return err
	}
	resp, err := http.Post(strings.TrimRight(baseURL, "/")+"/analyses/batch", "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("bulk add failed: %s", strings.TrimSpace(string(body)))
	}
	var summary map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&summary); err != nil {
		return err
	}
	fmt.Println("Batch submitted:", summary["batch_id"])
	return nil
}
