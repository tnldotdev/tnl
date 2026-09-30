package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/tnldotdev/tnl/internal/benchworkload"
	"github.com/tnldotdev/tnl/internal/clientstate"
)

type reportCommand struct {
	RunDirectory string `name:"run" env:"BENCH_RUN" type:"path" required:"" help:"Directory from an earlier run."`
}

func (c reportCommand) run(stdout io.Writer) error {
	data, err := os.ReadFile(filepath.Join(c.RunDirectory, "result.json"))
	if err != nil {
		return err
	}
	var result benchmarkResult
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	server, err := clientstate.CanonicalServer(result.Plan.Server)
	if result.SchemaVersion != 1 && result.SchemaVersion != 2 || err != nil || server != result.Plan.Server {
		return errors.New("invalid benchmark result")
	}
	return printResult(stdout, result)
}

func printResult(stdout io.Writer, result benchmarkResult) error {
	cleanup := result.CleanupStatus
	if cleanup == "" {
		cleanup = "unknown"
		if result.CleanupExact {
			cleanup = "succeeded"
		}
	}
	if _, err := fmt.Fprintf(stdout, "%s: %s (%d public URLs; cleanup: %s)\n", result.RunID, result.Status, len(result.PublicURLs), cleanup); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "direct: %d/%d successful; p95 %s\n", result.Direct.Successes, result.Direct.Scheduled, p95(&result.Direct)); err != nil {
		return err
	}
	for index, phase := range result.Steady {
		if _, err := fmt.Fprintf(stdout, "server %d: %d/%d successful; p95 %s\n", index+1, phase.Successes, phase.Scheduled, p95(&phase)); err != nil {
			return err
		}
		if index < len(result.SteadyByURL) {
			for _, publicURL := range result.PublicURLInfo {
				summary := result.SteadyByURL[index][publicURL.PublicURL]
				if summary == nil {
					continue
				}
				if _, err := fmt.Fprintf(stdout, "  %s %s %s: %d/%d successful; %d missed; %d timed out\n",
					publicURL.PublicURL, publicURL.PublicURLID, publicURL.Transport,
					summary.Successes, summary.Scheduled, summary.Missed, summary.Timeouts); err != nil {
					return err
				}
			}
		}
	}
	if result.Plan.Workload.Transport == "auto" {
		if _, err := fmt.Fprintf(stdout, "auto: %d TLS/TCP selection events\n", len(result.Fallbacks)); err != nil {
			return err
		}
	}
	if result.Error != "" {
		_, err := fmt.Fprintf(stdout, "failure: %s\n", result.Error)
		return err
	}
	return nil
}

func p95(result *benchworkload.VisitorResult) string {
	value := result.Total.Percentile(95)
	if value == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.1f ms", *value)
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".result-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(append(data, '\n')); err != nil {
		return errors.Join(err, temporary.Close())
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}
