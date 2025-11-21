package cli

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/cochaviz/bottle-warden/internal/analysis"
	"github.com/cochaviz/bottle-warden/internal/api"
	"github.com/cochaviz/bottle-warden/internal/appconfig"
	"github.com/cochaviz/bottle-warden/internal/malwarebazaar"

	"github.com/cochaviz/bottle/daemon"
)

var (
	serveListen       string
	serveLedgerPath   string
	serveDaemonSocket string
	servePollInterval time.Duration
	serveConfigPath   string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "run the bottle-warden orchestrator, server, and monitoring stack",
	RunE: func(cmd *cobra.Command, args []string) error {
		runServer(rootLogger, serveListen, serveLedgerPath, serveDaemonSocket, servePollInterval, serveConfigPath)
		return nil
	},
}

func init() {
	serveCmd.Flags().StringVar(&serveListen, "listen", ":8080", "HTTP listen address")
	serveCmd.Flags().StringVar(&serveLedgerPath, "ledger", "data/ledger.jsonl", "ledger file path")
	serveCmd.Flags().StringVar(&serveDaemonSocket, "daemon-socket", "/var/run/bottle/daemon.sock", "path to the bottle daemon unix socket")
	serveCmd.Flags().DurationVar(&servePollInterval, "poll", 5*time.Second, "orchestrator poll interval")
	serveCmd.Flags().StringVar(&serveConfigPath, "config", "", "path to YAML configuration file")
	rootCmd.AddCommand(serveCmd)
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
		downloader = &malwarebazaar.Client{
			BaseURL: bazaarCfg.BaseURL,
			APIKey:  envAPIKey,
			Logger:  logger,
		}
	}

	var watcher *malwarebazaar.Watcher
	if bazaarCfg.Watcher.Enabled && downloader != nil {
		watcher = malwarebazaar.NewWatcher(downloader, ledger, orchestrator, bazaarCfg.Watcher, bazaarCfg.SampleDir, logger)
		if watcher == nil {
			logger.Warn("malwarebazaar watcher not configured")
		}
	} else if bazaarCfg.Watcher.Enabled {
		logger.Warn("malwarebazaar watcher enabled but client not configured (missing API key?)")
	}

	httpServer, err := api.NewServer(api.Config{
		ListenAddr:   listenAddr,
		Ledger:       ledger,
		Orchestrator: orchestrator,
		Logger:       logger,
		Downloader:   downloader,
		SampleDir:    sampleDir,
	})
	if err != nil {
		logger.Error("failed to build server", "error", err)
		os.Exit(1)
	}

	var monitor *analysis.Monitor
	if monitoringCfg.Active() {
		monitor = analysis.NewMonitor(ledger, orchestrator, monitoringCfg, logger)
	}

	errCh := make(chan error, 3)

	go func() {
		errCh <- httpServer.Run(ctx)
	}()
	go func() {
		if monitor == nil {
			return
		}
		if err := monitor.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- err
		}
	}()
	go func() {
		if watcher == nil {
			return
		}
		if err := watcher.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil {
			logger.Error("component failed", "error", err)
			os.Exit(1)
		}
	}
}
