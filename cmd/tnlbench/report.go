package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type reportCommand struct {
	RunDirectory string `name:"run" env:"BENCH_RUN" type:"path" required:"" help:"Benchmark run directory containing results.jsonl."`
}

type benchmarkReport struct {
	SchemaVersion int          `json:"schema_version"`
	GeneratedAt   time.Time    `json:"generated_at"`
	Status        string       `json:"status"`
	ResultRows    int          `json:"result_rows"`
	PassedRows    int          `json:"passed_rows"`
	FailedRows    int          `json:"failed_rows"`
	Cells         []cellReport `json:"cells"`
}

type cellReport struct {
	CellID     string                 `json:"cell_id"`
	Suite      string                 `json:"suite"`
	Workload   string                 `json:"workload"`
	Status     string                 `json:"status"`
	Rows       int                    `json:"rows"`
	PassedRows int                    `json:"passed_rows"`
	FailedRows int                    `json:"failed_rows"`
	Attempts   int                    `json:"attempts"`
	Successes  int                    `json:"successes"`
	Errors     int                    `json:"errors"`
	Bytes      int64                  `json:"bytes"`
	Phases     map[string]phaseReport `json:"phases"`
	Failures   []string               `json:"failures"`
}

type phaseReport struct {
	Attempts             int     `json:"attempts"`
	Successes            int     `json:"successes"`
	Errors               int     `json:"errors"`
	Bytes                int64   `json:"bytes"`
	LatencyP50Millis     float64 `json:"latency_p50_milliseconds"`
	LatencyP95Millis     float64 `json:"latency_p95_milliseconds"`
	LatencyMaximumMillis float64 `json:"latency_maximum_milliseconds"`
	FirstByteP95Millis   float64 `json:"first_byte_p95_milliseconds,omitempty"`
}

type phaseAccumulator struct {
	phaseResult
	latency   *durationHistogram
	firstByte *durationHistogram
}

func (c reportCommand) run(stdout io.Writer) error {
	results, err := readBenchmarkResults(filepath.Join(c.RunDirectory, "results.jsonl"))
	if err != nil {
		return err
	}
	report, err := buildReport(results)
	if err != nil {
		return err
	}
	jsonPath := filepath.Join(c.RunDirectory, "report.json")
	if err := writeReportJSON(jsonPath, report); err != nil {
		return err
	}
	markdownPath := filepath.Join(c.RunDirectory, "report.md")
	if err := os.WriteFile(markdownPath, []byte(formatReportMarkdown(report)), 0o600); err != nil {
		return fmt.Errorf("write report markdown: %w", err)
	}
	fmt.Fprintf(stdout, "Report: %s\nMarkdown: %s\n", jsonPath, markdownPath)
	return nil
}

func readBenchmarkResults(path string) ([]benchmarkResult, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var results []benchmarkResult
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 2<<20)
	for line := 1; scanner.Scan(); line++ {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var result benchmarkResult
		if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
			return nil, fmt.Errorf("decode result line %d: %w", line, err)
		}
		if result.SchemaVersion != 2 || result.CellID == "" || result.Shard.Count <= 0 ||
			result.Shard.Index < 0 || result.Shard.Index >= result.Shard.Count {
			return nil, fmt.Errorf("result line %d has invalid schema or identity", line)
		}
		results = append(results, result)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, errors.New("results.jsonl contains no result rows")
	}
	return results, nil
}

func buildReport(results []benchmarkResult) (benchmarkReport, error) {
	report := benchmarkReport{SchemaVersion: 1, GeneratedAt: time.Now().UTC(), Status: "passed", ResultRows: len(results)}
	cellResults := make(map[string][]benchmarkResult)
	for _, result := range results {
		cellResults[result.CellID] = append(cellResults[result.CellID], result)
		if result.Status == "passed" {
			report.PassedRows++
		} else {
			report.FailedRows++
			report.Status = "failed"
		}
	}
	cellIDs := make([]string, 0, len(cellResults))
	for cellID := range cellResults {
		cellIDs = append(cellIDs, cellID)
	}
	sort.Strings(cellIDs)
	for _, cellID := range cellIDs {
		rows := cellResults[cellID]
		cell := cellReport{
			CellID: cellID, Suite: rows[0].Suite, Workload: rows[0].Workload, Status: "passed",
			Rows: len(rows), Phases: make(map[string]phaseReport), Failures: []string{},
		}
		phases := make(map[string]*phaseAccumulator)
		seenShards := make(map[int]struct{}, len(rows))
		for _, row := range rows {
			if row.Suite != cell.Suite || row.Workload != cell.Workload || row.Shard.Count != rows[0].Shard.Count {
				return benchmarkReport{}, fmt.Errorf("cell %q has inconsistent result identities", cellID)
			}
			if _, found := seenShards[row.Shard.Index]; found {
				return benchmarkReport{}, fmt.Errorf("cell %q repeats shard %d", cellID, row.Shard.Index)
			}
			seenShards[row.Shard.Index] = struct{}{}
			if row.Status == "passed" {
				cell.PassedRows++
			} else {
				cell.FailedRows++
				cell.Status = "failed"
				if row.Failure != nil {
					cell.Failures = append(cell.Failures, row.Failure.Message)
				}
			}
			for _, phase := range row.Phases {
				accumulator := phases[phase.Name]
				if accumulator == nil {
					accumulator = &phaseAccumulator{}
					phases[phase.Name] = accumulator
				}
				accumulator.Attempts += phase.Attempts
				accumulator.Successes += phase.Successes
				accumulator.Errors += phase.Errors
				accumulator.Bytes += phase.Bytes
				if err := mergeDurationHistogram(&accumulator.latency, phase.Latency); err != nil {
					return benchmarkReport{}, fmt.Errorf("cell %q phase %q latency: %w", cellID, phase.Name, err)
				}
				if err := mergeDurationHistogram(&accumulator.firstByte, phase.FirstByteLatency); err != nil {
					return benchmarkReport{}, fmt.Errorf("cell %q phase %q first byte: %w", cellID, phase.Name, err)
				}
			}
		}
		if len(seenShards) != rows[0].Shard.Count {
			cell.Status = "failed"
			cell.Failures = append(cell.Failures, fmt.Sprintf("expected %d shards, found %d", rows[0].Shard.Count, len(seenShards)))
			report.Status = "failed"
		}
		for name, phase := range phases {
			cell.Attempts += phase.Attempts
			cell.Successes += phase.Successes
			cell.Errors += phase.Errors
			cell.Bytes += phase.Bytes
			cell.Phases[name] = phaseReport{
				Attempts: phase.Attempts, Successes: phase.Successes, Errors: phase.Errors, Bytes: phase.Bytes,
				LatencyP50Millis:     histogramPercentile(phase.latency, 50),
				LatencyP95Millis:     histogramPercentile(phase.latency, 95),
				LatencyMaximumMillis: histogramMaximum(phase.latency),
				FirstByteP95Millis:   histogramPercentile(phase.firstByte, 95),
			}
		}
		report.Cells = append(report.Cells, cell)
	}
	return report, nil
}

func histogramMaximum(histogram *durationHistogram) float64 {
	if histogram == nil {
		return 0
	}
	return histogram.MaximumMilliseconds
}

func writeReportJSON(path string, report benchmarkReport) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create report JSON: %w", err)
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encodeErr := encoder.Encode(report)
	closeErr := file.Close()
	return errors.Join(encodeErr, closeErr)
}

func formatReportMarkdown(report benchmarkReport) string {
	var output strings.Builder
	fmt.Fprintf(&output, "# Fly Benchmark Report\n\nStatus: **%s**\n\n", report.Status)
	fmt.Fprintf(&output, "Result rows: %d passed, %d failed, %d total.\n\n", report.PassedRows, report.FailedRows, report.ResultRows)
	output.WriteString("Workload inputs are assumptions unless the named workload explicitly says otherwise. Existing streams are not transferred during worker loss, and no stream bytes are replayed.\n\n")
	output.WriteString("| Cell | Status | Rows | Attempts | Successes | Errors | Bytes |\n")
	output.WriteString("| --- | --- | ---: | ---: | ---: | ---: | ---: |\n")
	for _, cell := range report.Cells {
		fmt.Fprintf(&output, "| %s | %s | %d | %d | %d | %d | %d |\n",
			cell.CellID, cell.Status, cell.Rows, cell.Attempts, cell.Successes, cell.Errors, cell.Bytes)
	}
	for _, cell := range report.Cells {
		fmt.Fprintf(&output, "\n## %s\n\nSuite: `%s`; workload: `%s`.\n\n", cell.CellID, cell.Suite, cell.Workload)
		output.WriteString("| Phase | Attempts | Successes | Errors | p50 ms | p95 ms | Max ms | First byte p95 ms |\n")
		output.WriteString("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n")
		phaseNames := make([]string, 0, len(cell.Phases))
		for name := range cell.Phases {
			phaseNames = append(phaseNames, name)
		}
		sort.Strings(phaseNames)
		for _, name := range phaseNames {
			phase := cell.Phases[name]
			fmt.Fprintf(&output, "| %s | %d | %d | %d | %.2f | %.2f | %.2f | %.2f |\n",
				name, phase.Attempts, phase.Successes, phase.Errors, phase.LatencyP50Millis,
				phase.LatencyP95Millis, phase.LatencyMaximumMillis, phase.FirstByteP95Millis)
		}
		for _, failure := range cell.Failures {
			fmt.Fprintf(&output, "\nFailure: %s\n", failure)
		}
	}
	return output.String()
}
