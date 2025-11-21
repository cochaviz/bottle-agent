package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/cochaviz/bottle-warden/internal/analysis"
	"github.com/cochaviz/bottle/daemon"
)

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
	workersCmd.AddCommand(
		workersListCmd,
		workersInspectCmd,
	)
	rootCmd.AddCommand(workersCmd)
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
