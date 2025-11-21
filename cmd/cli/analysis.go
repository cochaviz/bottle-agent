package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/cochaviz/bottle-warden/internal/analysis"
)

var (
	addSampleID            string
	addSamplePath          string
	addSourceHash          string
	addC2Address           string
	addInstrumentation     string
	addBulkDir             string
	addBulkHashes          string
	addBulkInstrumentation string
	deleteFailedFlag       bool
	restartC2Address       string
)

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
	Use:   "delete [id]",
	Short: "remove an analysis or all failed analyses",
	Args:  cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if deleteFailedFlag {
			if len(args) > 0 {
				return errors.New("do not specify an id when using --failed")
			}
			return clientDeleteFailed(apiServerURL)
		}
		if len(args) != 1 {
			return errors.New("id is required (or use --failed to delete all failed analyses)")
		}
		return clientDelete(apiServerURL, args[0], false)
	},
}

var analysisRestartCmd = &cobra.Command{
	Use:   "restart <id>",
	Short: "restart (re-queue) an analysis",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return clientRestart(apiServerURL, args[0], restartC2Address)
	},
}

func init() {
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

	analysisDeleteCmd.Flags().BoolVar(&deleteFailedFlag, "failed", false, "delete all failed analyses")

	analysisRestartCmd.Flags().StringVar(&restartC2Address, "c2", "", "override C2 address when restarting")

	rootCmd.AddCommand(analysisCmd)
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

func clientDelete(baseURL, id string, allowFailed bool) error {
	req, err := http.NewRequest(http.MethodDelete, strings.TrimRight(baseURL, "/")+"/analyses/"+id, nil)
	if err != nil {
		return err
	}
	if allowFailed {
		req.Header.Set("X-Allow-Failed", "true")
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

func clientDeleteFailed(baseURL string) error {
	req, err := http.NewRequest(http.MethodDelete, strings.TrimRight(baseURL, "/")+"/analyses?state=failed", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete failed analyses failed: %s", strings.TrimSpace(string(body)))
	}
	var payload struct {
		Deleted int    `json:"deleted"`
		State   string `json:"state"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err == nil && payload.Deleted > 0 {
		fmt.Printf("Deleted %d %s analyses\n", payload.Deleted, payload.State)
		return nil
	}
	fmt.Println("Deleted 0 failed analyses")
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

func clientRestart(baseURL, id, c2 string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("id is required")
	}
	body := map[string]interface{}{"state": string(analysis.StateQueued)}
	if strings.TrimSpace(c2) != "" {
		body["c2_address"] = c2
	}
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

func clientAddBulk(baseURL, dirPath, hashCSV, instrumentation string) error {
	dir := strings.TrimSpace(dirPath)
	hashes := strings.TrimSpace(hashCSV)
	if dir == "" && hashes == "" {
		return errors.New("either --dir or --hashes must be provided")
	}
	payload := map[string]interface{}{
		"instrumentation": instrumentation,
		"metadata":        map[string]string{},
		"sample_timeout":  "",
		"sandbox_timeout": "",
	}
	if dir != "" {
		payload["directory"] = dir
	} else {
		parts := strings.Split(hashes, ",")
		list := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				list = append(list, part)
			}
		}
		if len(list) == 0 {
			return errors.New("no hashes provided")
		}
		payload["hashes"] = list
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := http.Post(strings.TrimRight(baseURL, "/")+"/analyses/batch", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("add-bulk failed: %s", strings.TrimSpace(string(respBody)))
	}
	var response map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return err
	}
	batchID, _ := response["batch_id"].(string)
	fmt.Printf("Created batch %s\n", batchID)
	return nil
}
