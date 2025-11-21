package cli

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	logLevelFlag string
	apiServerURL string
	rootLogger   *slog.Logger
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

func init() {
	rootCmd.PersistentFlags().StringVar(&logLevelFlag, "log-level", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().StringVar(&apiServerURL, "server", "http://127.0.0.1:8080", "bottle-warden API base URL")
}

// Execute runs the CLI.
func Execute() error {
	return rootCmd.Execute()
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
