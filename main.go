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
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/cochaviz/bottle-warden/internal/analysis"
	"github.com/cochaviz/bottle-warden/internal/api"
	"github.com/cochaviz/bottle-warden/internal/appconfig"
	"github.com/cochaviz/bottle-warden/internal/malwarebazaar"
	"github.com/spf13/cobra"

	"github.com/cochaviz/bottle/daemon"
)

var (
	logLevelFlag string

	serveListen       string
	serveLedgerPath   string
	serveDaemonSocket string
	servePollInterval time.Duration
	serveConfigPath   string

	apiServerURL           string
	addSampleID            string
	addSamplePath          string
	addSourceHash          string
	addC2Address           string
	addInstrumentation     string
	addBulkDir             string
	addBulkHashes          string
	addBulkInstrumentation string
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
		slog.SetDefault(rootLogger)
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

var analysisCmd = &cobra.Command{
	Use:   "analysis",
	Short: "manage analyses",
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

var analysisListCmd = &cobra.Command{
	Use:   "list",
	Short: "list analyses in the agent ledger",
	RunE: func(cmd *cobra.Command, args []string) error {
		return clientStatus(apiServerURL)
	},
}

var analysisAddCmd = &cobra.Command{
	Use:   "add",
	Short: "enqueue a single analysis",
	RunE: func(cmd *cobra.Command, args []string) error {
		return clientAdd(apiServerURL, addSampleID, addSamplePath, addSourceHash, addC2Address, addInstrumentation)
	},
}

var analysisAddBulkCmd = &cobra.Command{
	Use:   "add-bulk",
	Short: "enqueue multiple analyses from a directory or hash list",
	RunE: func(cmd *cobra.Command, args []string) error {
		return clientAddBulk(apiServerURL, addBulkDir, addBulkHashes, addBulkInstrumentation)
	},
}

var analysisDeleteCmd = &cobra.Command{
	Use:   "delete <id>",
	Short: "remove an analysis",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return clientDelete(apiServerURL, args[0])
	},
}

var analysisRestartCmd = &cobra.Command{
	Use:   "restart <id>",
	Short: "restart (re-queue) an analysis",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return clientRestart(apiServerURL, args[0])
	},
}

var workersCmd = &cobra.Command{
	Use:   "workers",
	Short: "inspect daemon workers",
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

var workersListCmd = &cobra.Command{
	Use:   "list",
	Short: "list daemon workers currently tracked by the orchestrator",
	RunE: func(cmd *cobra.Command, args []string) error {
		return clientListWorkers(apiServerURL)
	},
}

var workersInspectCmd = &cobra.Command{
	Use:   "inspect <id>",
	Short: "inspect a daemon worker via the orchestrator",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return clientInspectWorker(apiServerURL, args[0])
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&logLevelFlag, "log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&apiServerURL, "server", "http://127.0.0.1:8080", "bottle-warden API base URL")
	rootCmd.AddCommand(
		serveCmd,
		workersCmd,
		analysisCmd,
	)

	serveCmd.Flags().StringVar(&serveListen, "listen", ":8080", "HTTP listen address")
	serveCmd.Flags().StringVar(&serveLedgerPath, "ledger", "data/ledger.jsonl", "ledger file path")
	serveCmd.Flags().StringVar(&serveDaemonSocket, "daemon-socket", "/var/run/bottle/daemon.sock", "path to the bottle daemon unix socket")
	serveCmd.Flags().DurationVar(&servePollInterval, "poll", 5*time.Second, "orchestrator poll interval")
	serveCmd.Flags().StringVar(&serveConfigPath, "config", "", "path to YAML configuration file")

	analysisCmd.AddCommand(
		analysisListCmd,
		analysisAddCmd,
		analysisAddBulkCmd,
		analysisDeleteCmd,
		analysisRestartCmd,
	)

	analysisAddCmd.Flags().StringVar(&addSampleID, "sample", "", "sample identifier (required)")
	analysisAddCmd.Flags().StringVar(&addSamplePath, "path", "", "local sample path")
	analysisAddCmd.Flags().StringVar(&addSourceHash, "hash", "", "MalwareBazaar hash to fetch")
	analysisAddCmd.Flags().StringVar(&addC2Address, "c2", "", "C2 address")
	analysisAddCmd.Flags().StringVar(&addInstrumentation, "instrumentation", "", "instrumentation profile")
	_ = analysisAddCmd.MarkFlagRequired("sample")

	analysisAddBulkCmd.Flags().StringVar(&addBulkDir, "dir", "", "directory of samples")
	analysisAddBulkCmd.Flags().StringVar(&addBulkHashes, "hashes", "", "comma-separated hashes")
	analysisAddBulkCmd.Flags().StringVar(&addBulkInstrumentation, "instrumentation", "", "instrumentation profile")

	workersCmd.AddCommand(
		workersListCmd,
		workersInspectCmd,
	)
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
	absSampleDir, err := filepath.Abs(sampleDir)
	if err != nil {
		logger.Error("failed to resolve sample directory", "dir", sampleDir, "error", err)
		os.Exit(1)
	}
	sampleDir = absSampleDir
	if err := os.MkdirAll(sampleDir, 0o755); err != nil {
		logger.Error("failed to prepare sample directory", "dir", sampleDir, "error", err)
		os.Exit(1)
	}

	var daemonClient *daemon.Client
	if strings.TrimSpace(daemonSocket) != "" {
		daemonClient = daemon.NewClient(daemonSocket)
	} else {
		logger.Warn("daemon socket not configured, running in dry-run mode")
	}

	orchestrator := analysis.NewOrchestrator(ledger, daemonClient, analysis.OrchestratorConfig{
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

func clientListWorkers(baseURL string) error {
	resp, err := http.Get(strings.TrimRight(baseURL, "/") + "/workers")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("list workers failed: %s", strings.TrimSpace(string(body)))
	}
	var workers []analysis.RuntimeStatus
	if err := json.NewDecoder(resp.Body).Decode(&workers); err != nil {
		return err
	}
	if len(workers) == 0 {
		fmt.Println("No daemon workers.")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSAMPLE\tC2\tSTARTED\tRUNNING\tERROR")
	for _, worker := range workers {
		c2 := worker.C2IP
		if c2 == "" {
			c2 = "-"
		}
		start := "-"
		if !worker.StartedAt.IsZero() {
			start = worker.StartedAt.Format(time.RFC3339)
		}
		errMsg := worker.Error
		if errMsg == "" {
			errMsg = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%t\t%s\n",
			worker.ID, worker.Sample, c2, start, worker.Running, errMsg)
	}
	w.Flush()
	return nil
}

func clientInspectWorker(baseURL, workerID string) error {
	id := strings.TrimSpace(workerID)
	if id == "" {
		return errors.New("id is required")
	}
	endpoint := fmt.Sprintf("%s/workers/%s", strings.TrimRight(baseURL, "/"), url.PathEscape(id))
	resp, err := http.Get(endpoint)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("inspect worker failed: %s", strings.TrimSpace(string(body)))
	}
	var detail daemon.WorkerDetails
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		return err
	}
	status := detail.Status
	fmt.Printf("ID:\t%s\n", status.ID)
	fmt.Printf("Sample:\t%s\n", status.Sample)
	if strings.TrimSpace(status.C2Ip) != "" {
		fmt.Printf("C2:\t%s\n", status.C2Ip)
	}
	if !status.StartedAt.IsZero() {
		fmt.Printf("Started:\t%s\n", status.StartedAt.Format(time.RFC3339))
	}
	if status.CompletedAt != nil {
		fmt.Printf("Completed:\t%s\n", status.CompletedAt.Format(time.RFC3339))
	}
	fmt.Printf("Running:\t%t\n", status.Running)
	if strings.TrimSpace(status.Error) != "" {
		fmt.Printf("Error:\t%s\n", status.Error)
	}
	if detail.Duration > 0 {
		fmt.Printf("Runtime:\t%s\n", detail.Duration)
	}
	opts := detail.Options
	fmt.Println("Options:")
	printOption := func(key, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		fmt.Printf("  %s: %s\n", key, value)
	}
	printDuration := func(key string, value time.Duration) {
		if value <= 0 {
			return
		}
		fmt.Printf("  %s: %s\n", key, value)
	}
	if len(opts.SampleArgs) > 0 {
		fmt.Printf("  SampleArgs: %s\n", strings.Join(opts.SampleArgs, " "))
	}
	printOption("SamplePath", opts.SamplePath)
	printOption("C2Address", opts.C2Address)
	printOption("ImageDir", opts.ImageDir)
	printOption("RunDir", opts.RunDir)
	printOption("ConnectionURI", opts.ConnectionURI)
	printOption("OverrideArch", opts.OverrideArch)
	printOption("Instrumentation", opts.Instrumentation)
	printOption("LogLevel", opts.LogLevel)
	printDuration("SampleTimeout", opts.SampleTimeout)
	printDuration("SandboxLifetime", opts.SandboxLifetime)
	return nil
}

func clientAdd(baseURL, sampleID, samplePath, sourceHash, c2, instrumentation string) error {
	if strings.TrimSpace(sampleID) == "" {
		return errors.New("sample is required")
	}
	if strings.TrimSpace(samplePath) == "" && strings.TrimSpace(sourceHash) == "" {
		return errors.New("either --path or --hash must be provided")
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

func clientRestart(baseURL, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("id is required")
	}
	body := map[string]string{"state": string(analysis.StateQueued)}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPut, strings.TrimRight(baseURL, "/")+"/analyses/"+id, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("restart failed: %s", strings.TrimSpace(string(body)))
	}
	fmt.Println("Restarted analysis", id)
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
