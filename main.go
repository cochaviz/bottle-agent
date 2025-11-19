package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"cochaviz/bottle-agent/internal/analysis"
	"cochaviz/bottle-agent/internal/api"
	"cochaviz/bottle-agent/internal/appconfig"
	"cochaviz/bottle-agent/internal/daemonclient"
	"cochaviz/bottle-agent/internal/malwarebazaar"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		runServe(os.Args[2:])
	case "client":
		runClientCLI(os.Args[2:])
	default:
		printUsage()
		os.Exit(2)
	}
}

func printUsage() {
	name := filepath.Base(os.Args[0])
	fmt.Fprintf(os.Stderr, "Usage:\n  %s serve [options]\n  %s client <command> [args]\n", name, name)
	fmt.Fprintln(os.Stderr, "\nClient commands: status, add, delete, add-bulk")
}

func runServe(args []string) {
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	listenAddr := flags.String("listen", ":8080", "HTTP listen address")
	ledgerPath := flags.String("ledger", "data/ledger.jsonl", "ledger file path")
	daemonSocket := flags.String("daemon-socket", "/var/run/bottle/daemon.sock", "path to the bottle daemon unix socket")
	pollInterval := flags.Duration("poll", 5*time.Second, "orchestrator poll interval")
	logLevel := flags.String("log-level", "info", "log level (debug, info, warn, error)")
	configPath := flags.String("config", "", "path to YAML configuration file")
	if err := flags.Parse(args); err != nil {
		os.Exit(2)
	}
	runServer(*listenAddr, *ledgerPath, *daemonSocket, *pollInterval, *logLevel, *configPath)
}

func runClientCLI(args []string) {
	flags := flag.NewFlagSet("client", flag.ExitOnError)
	serverURL := flags.String("server", "http://127.0.0.1:8080", "bottle-agent API base URL")
	if err := flags.Parse(args); err != nil {
		os.Exit(2)
	}
	clientArgs := flags.Args()
	if len(clientArgs) == 0 {
		fmt.Fprintln(os.Stderr, "client command required (status, add, delete, add-bulk)")
		os.Exit(2)
	}
	if err := runClientCommand(*serverURL, clientArgs[0], clientArgs[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runServer(listenAddr, ledgerPath, daemonSocket string, pollInterval time.Duration, logLevel, configPath string) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	level := slog.LevelInfo
	switch strings.ToLower(logLevel) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

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

func runClientCommand(baseURL, command string, args []string) error {
	switch command {
	case "status":
		return clientStatus(baseURL)
	case "delete":
		if len(args) != 1 {
			return errors.New("delete requires analysis ID")
		}
		return clientDelete(baseURL, args[0])
	case "add":
		return clientAdd(baseURL, args)
	case "add-bulk":
		return clientAddBulk(baseURL, args)
	default:
		return fmt.Errorf("unknown client command %q", command)
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

func clientAdd(baseURL string, args []string) error {
	flags := flag.NewFlagSet("client add", flag.ExitOnError)
	sampleID := flags.String("sample", "", "sample identifier (required)")
	samplePath := flags.String("path", "", "local sample path")
	sourceHash := flags.String("hash", "", "MalwareBazaar hash to fetch")
	c2 := flags.String("c2", "", "C2 address")
	instrumentation := flags.String("instrumentation", "", "instrumentation profile")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*sampleID) == "" {
		return errors.New("sample is required")
	}
	body := map[string]interface{}{
		"sample_id":       *sampleID,
		"sample_path":     *samplePath,
		"c2_address":      *c2,
		"instrumentation": *instrumentation,
		"sample_args":     []string{},
		"metadata":        map[string]string{},
		"notes":           "",
	}
	if strings.TrimSpace(*sourceHash) != "" {
		body["source"] = map[string]string{"type": "hash", "value": *sourceHash}
	} else if strings.TrimSpace(*samplePath) != "" {
		body["source"] = map[string]string{"type": "file", "value": *samplePath}
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

func clientAddBulk(baseURL string, args []string) error {
	flags := flag.NewFlagSet("client add-bulk", flag.ExitOnError)
	dir := flags.String("dir", "", "directory of samples")
	hashes := flags.String("hashes", "", "comma-separated hashes")
	instrumentation := flags.String("instrumentation", "", "instrumentation profile")
	if err := flags.Parse(args); err != nil {
		return err
	}
	req := map[string]interface{}{
		"directory":       *dir,
		"hashes":          []string{},
		"instrumentation": *instrumentation,
	}
	if strings.TrimSpace(*hashes) != "" {
		parts := strings.Split(*hashes, ",")
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
