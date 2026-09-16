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
	SchemaVersion            int            `json:"schema_version"`
	GeneratedAt              time.Time      `json:"generated_at"`
	Status                   string         `json:"status"`
	ResultRows               int            `json:"result_rows"`
	PassedRows               int            `json:"passed_rows"`
	FailedRows               int            `json:"failed_rows"`
	Cells                    []cellReport   `json:"cells"`
	HighestPassing           *capacityPoint `json:"highest_passing,omitempty"`
	HighestRepeatablyPassing *capacityPoint `json:"highest_repeatably_passing,omitempty"`
	FirstSaturation          *capacityPoint `json:"first_saturation,omitempty"`
}

type cellReport struct {
	CellID           string                 `json:"cell_id"`
	Target           string                 `json:"target"`
	Suite            string                 `json:"suite"`
	Sequence         int                    `json:"sequence"`
	Repetition       int                    `json:"repetition"`
	Status           string                 `json:"status"`
	ResultRows       int                    `json:"result_rows"`
	PublisherWorkers int                    `json:"publisher_workers"`
	LoadWorkers      int                    `json:"load_workers"`
	Routes           int                    `json:"routes"`
	FreshRate        int                    `json:"fresh_connections_per_second"`
	HeldStreams      int                    `json:"held_streams"`
	Phases           map[string]phaseReport `json:"phases"`
	ResourceMaximums map[string]float64     `json:"resource_maximums,omitempty"`
	Failures         []string               `json:"failures"`
}

type phaseReport struct {
	Attempts     int     `json:"attempts"`
	Successes    int     `json:"successes"`
	Errors       int     `json:"errors"`
	Bytes        int64   `json:"bytes"`
	AchievedRate float64 `json:"achieved_rate,omitempty"`
	Concurrency  int     `json:"concurrency,omitempty"`
	DNSP95       float64 `json:"dns_p95_milliseconds,omitempty"`
	ConnectP95   float64 `json:"connect_p95_milliseconds,omitempty"`
	TLSP95       float64 `json:"tls_p95_milliseconds,omitempty"`
	FirstByteP50 float64 `json:"first_byte_p50_milliseconds,omitempty"`
	FirstByteP95 float64 `json:"first_byte_p95_milliseconds,omitempty"`
	TotalP50     float64 `json:"total_p50_milliseconds,omitempty"`
	TotalP95     float64 `json:"total_p95_milliseconds,omitempty"`
	TotalMaximum float64 `json:"total_maximum_milliseconds,omitempty"`
}

type capacityPoint struct {
	Target      string `json:"target"`
	Sequence    int    `json:"sequence"`
	Routes      int    `json:"routes"`
	FreshRate   int    `json:"fresh_connections_per_second"`
	HeldStreams int    `json:"held_streams"`
	Repetitions int    `json:"repetitions"`
	Passed      int    `json:"passed"`
}

type phaseAccumulator struct {
	attempts, successes, errors, concurrency int
	bytes                                    int64
	achievedRate                             float64
	dns, connect, handshake                  *durationHistogram
	firstByte, total                         *durationHistogram
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
	scanner.Buffer(make([]byte, 64<<10), 4<<20)
	for line := 1; scanner.Scan(); line++ {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var result benchmarkResult
		if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
			return nil, fmt.Errorf("decode result line %d: %w", line, err)
		}
		if err := validateResultIdentity(result); err != nil {
			return nil, fmt.Errorf("result line %d: %w", line, err)
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

func validateResultIdentity(result benchmarkResult) error {
	if result.SchemaVersion != benchmarkResultSchemaVersion || result.CellID == "" || result.Suite == "" || result.Repetition <= 0 ||
		(result.Status != "passed" && result.Status != "failed") ||
		(result.Worker.Kind != "publisher" && result.Worker.Kind != "load") || result.Worker.Count <= 0 ||
		result.Worker.Index < 0 || result.Worker.Index >= result.Worker.Count || result.Configuration.Sequence < 0 ||
		result.Configuration.Routes <= 0 {
		return errors.New("invalid result schema or identity")
	}
	return nil
}

func buildReport(results []benchmarkResult) (benchmarkReport, error) {
	report := benchmarkReport{SchemaVersion: 2, GeneratedAt: time.Now().UTC(), Status: "passed", ResultRows: len(results)}
	grouped := make(map[string][]benchmarkResult)
	for _, result := range results {
		if err := validateResultIdentity(result); err != nil {
			return benchmarkReport{}, err
		}
		grouped[result.CellID] = append(grouped[result.CellID], result)
		if result.Status == "passed" {
			report.PassedRows++
		} else {
			report.FailedRows++
			report.Status = "failed"
		}
	}
	for cellID, rows := range grouped {
		cell, err := buildCellReport(cellID, rows)
		if err != nil {
			return benchmarkReport{}, err
		}
		if cell.Status != "passed" {
			report.Status = "failed"
		}
		report.Cells = append(report.Cells, cell)
	}
	sort.Slice(report.Cells, func(i, j int) bool {
		if report.Cells[i].Sequence != report.Cells[j].Sequence {
			return report.Cells[i].Sequence < report.Cells[j].Sequence
		}
		return report.Cells[i].Repetition < report.Cells[j].Repetition
	})
	report.HighestPassing, report.HighestRepeatablyPassing, report.FirstSaturation = capacitySummary(report.Cells)
	return report, nil
}

func buildCellReport(cellID string, rows []benchmarkResult) (cellReport, error) {
	first := rows[0]
	cell := cellReport{
		CellID: cellID, Target: strings.TrimSuffix(cellID, fmt.Sprintf("-rep%d", first.Repetition)), Suite: first.Suite,
		Sequence: first.Configuration.Sequence, Repetition: first.Repetition, Status: "passed", ResultRows: len(rows),
		Routes: first.Configuration.Routes, Phases: make(map[string]phaseReport),
		FreshRate: first.Configuration.FreshConnectionsPerSecond, HeldStreams: first.Configuration.HeldStreams,
		ResourceMaximums: make(map[string]float64), Failures: []string{},
	}
	seen := make(map[string]struct{})
	want := make(map[string]int)
	phases := make(map[string]*phaseAccumulator)
	var resourceSamples []resourceSample
	for _, row := range rows {
		if row.Suite != cell.Suite || row.Repetition != cell.Repetition || row.Configuration.Sequence != cell.Sequence ||
			row.Configuration.Routes != cell.Routes || row.Configuration.FreshConnectionsPerSecond != cell.FreshRate ||
			row.Configuration.HeldStreams != cell.HeldStreams {
			return cellReport{}, fmt.Errorf("cell %q has inconsistent result identities", cellID)
		}
		key := fmt.Sprintf("%s:%d", row.Worker.Kind, row.Worker.Index)
		if _, exists := seen[key]; exists {
			return cellReport{}, fmt.Errorf("cell %q repeats worker %s", cellID, key)
		}
		seen[key] = struct{}{}
		if previous := want[row.Worker.Kind]; previous != 0 && previous != row.Worker.Count {
			return cellReport{}, fmt.Errorf("cell %q has inconsistent %s worker counts", cellID, row.Worker.Kind)
		}
		want[row.Worker.Kind] = row.Worker.Count
		if row.Status != "passed" {
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
			accumulator.attempts += phase.Attempts
			accumulator.successes += phase.Successes
			accumulator.errors += phase.Errors
			accumulator.bytes += phase.Bytes
			accumulator.achievedRate += phase.AchievedRate
			accumulator.concurrency += phase.Concurrency
			for label, pair := range map[string]struct {
				destination **durationHistogram
				source      *durationHistogram
			}{
				"dns": {&accumulator.dns, phase.DNS}, "connect": {&accumulator.connect, phase.Connect},
				"tls": {&accumulator.handshake, phase.TLS}, "first byte": {&accumulator.firstByte, phase.FirstByte},
				"total": {&accumulator.total, phase.Total},
			} {
				if err := mergeDurationHistogram(pair.destination, pair.source); err != nil {
					return cellReport{}, fmt.Errorf("cell %q phase %q %s: %w", cellID, phase.Name, label, err)
				}
			}
		}
		for _, sample := range row.Resources {
			resourceSamples = append(resourceSamples, sample)
			for name, value := range sample.Metrics {
				key := sample.Role + "/" + name
				cell.ResourceMaximums[key] = max(cell.ResourceMaximums[key], value)
			}
		}
	}
	cell.PublisherWorkers, cell.LoadWorkers = want["publisher"], want["load"]
	for _, kind := range []string{"publisher", "load"} {
		found := workerKindCount(seen, kind)
		if want[kind] == 0 || found != want[kind] {
			cell.Status = "failed"
			cell.Failures = append(cell.Failures, fmt.Sprintf("expected %d %s workers, found %d", want[kind], kind, found))
		}
	}
	if cell.Status == "passed" {
		rejections, err := ingressSourceLimiterRejections(resourceSamples)
		if err != nil {
			cell.Status = "failed"
			cell.Failures = append(cell.Failures, "ingress source limiter validation: "+err.Error())
		} else if rejections > 0 {
			cell.Status = "failed"
			cell.Failures = append(cell.Failures, fmt.Sprintf("ingress source limiter rejected %g visitor connections", rejections))
		}
	}
	for name, phase := range phases {
		cell.Phases[name] = phaseReport{
			Attempts: phase.attempts, Successes: phase.successes, Errors: phase.errors, Bytes: phase.bytes,
			AchievedRate: phase.achievedRate, Concurrency: phase.concurrency,
			DNSP95: histogramPercentile(phase.dns, 95), ConnectP95: histogramPercentile(phase.connect, 95),
			TLSP95: histogramPercentile(phase.handshake, 95), FirstByteP50: histogramPercentile(phase.firstByte, 50),
			FirstByteP95: histogramPercentile(phase.firstByte, 95), TotalP50: histogramPercentile(phase.total, 50),
			TotalP95: histogramPercentile(phase.total, 95), TotalMaximum: histogramMaximum(phase.total),
		}
	}
	return cell, nil
}

func ingressSourceLimiterRejections(samples []resourceSample) (float64, error) {
	const metric = "tnl_source_limiter_rejections_total"
	type pair struct {
		ready, loaded       float64
		hasReady, hasLoaded bool
	}
	byIdentity := make(map[string]pair)
	for _, sample := range samples {
		if sample.Role != "ingress" {
			continue
		}
		if sample.Error != "" {
			return 0, fmt.Errorf("sample %s at %s: %s", sample.Identity, sample.Moment, sample.Error)
		}
		value, ok := sample.Metrics[metric]
		if !ok {
			return 0, fmt.Errorf("sample %s at %s has no %s", sample.Identity, sample.Moment, metric)
		}
		current := byIdentity[sample.Identity]
		switch sample.Moment {
		case "ready":
			if current.hasReady {
				return 0, fmt.Errorf("sample %s repeats ready metrics", sample.Identity)
			}
			current.ready, current.hasReady = value, true
		case "loaded":
			if current.hasLoaded {
				return 0, fmt.Errorf("sample %s repeats loaded metrics", sample.Identity)
			}
			current.loaded, current.hasLoaded = value, true
		default:
			return 0, fmt.Errorf("sample %s has unknown moment %q", sample.Identity, sample.Moment)
		}
		byIdentity[sample.Identity] = current
	}
	if len(byIdentity) == 0 {
		return 0, errors.New("no ingress metrics were collected")
	}
	var total float64
	for identity, values := range byIdentity {
		if !values.hasReady || !values.hasLoaded {
			return 0, fmt.Errorf("sample %s does not have ready and loaded metrics", identity)
		}
		if values.loaded < values.ready {
			return 0, fmt.Errorf("sample %s counter reset while the cell ran", identity)
		}
		total += values.loaded - values.ready
	}
	return total, nil
}

func workerKindCount(seen map[string]struct{}, kind string) int {
	count := 0
	for key := range seen {
		if strings.HasPrefix(key, kind+":") {
			count++
		}
	}
	return count
}

func capacitySummary(cells []cellReport) (highest, repeatable, saturation *capacityPoint) {
	targets := make(map[string]*capacityPoint)
	failed := make(map[string]bool)
	for _, cell := range cells {
		point := targets[cell.Target]
		if point == nil {
			point = &capacityPoint{
				Target: cell.Target, Sequence: cell.Sequence, Routes: cell.Routes,
				FreshRate: cell.FreshRate, HeldStreams: cell.HeldStreams,
			}
			targets[cell.Target] = point
		}
		point.Repetitions++
		if cell.Status == "passed" {
			point.Passed++
		} else {
			failed[cell.Target] = true
		}
	}
	for target, point := range targets {
		if point.Passed == point.Repetitions && (highest == nil || point.Sequence > highest.Sequence) {
			copy := *point
			highest = &copy
		}
		if point.Repetitions >= 2 && point.Passed == point.Repetitions && (repeatable == nil || point.Sequence > repeatable.Sequence) {
			copy := *point
			repeatable = &copy
		}
		if failed[target] && (saturation == nil || point.Sequence < saturation.Sequence) {
			copy := *point
			saturation = &copy
		}
	}
	return highest, repeatable, saturation
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
	writeCapacityPoint(&output, "Highest passing cell", report.HighestPassing)
	writeCapacityPoint(&output, "Highest repeatably passing cell", report.HighestRepeatablyPassing)
	writeCapacityPoint(&output, "First saturation point", report.FirstSaturation)
	output.WriteString("\nThese are observed benchmark boundaries, not product SLOs.\n\n")
	output.WriteString("| Cell | Status | Routes | Fresh/s | Held | Publishers | Load workers |\n")
	output.WriteString("| --- | --- | ---: | ---: | ---: | ---: | ---: |\n")
	for _, cell := range report.Cells {
		fmt.Fprintf(&output, "| %s | %s | %d | %d | %d | %d | %d |\n",
			cell.CellID, cell.Status, cell.Routes, cell.FreshRate, cell.HeldStreams, cell.PublisherWorkers, cell.LoadWorkers)
	}
	for _, cell := range report.Cells {
		fmt.Fprintf(&output, "\n## %s\n\n", cell.CellID)
		output.WriteString("| Phase | Attempts | Successes | Errors | Rate | Concurrency | DNS p95 ms | Connect p95 ms | TLS p95 ms | TTFB p95 ms | Total p95 ms |\n")
		output.WriteString("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n")
		names := make([]string, 0, len(cell.Phases))
		for name := range cell.Phases {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			phase := cell.Phases[name]
			fmt.Fprintf(&output, "| %s | %d | %d | %d | %.2f | %d | %.2f | %.2f | %.2f | %.2f | %.2f |\n",
				name, phase.Attempts, phase.Successes, phase.Errors, phase.AchievedRate, phase.Concurrency,
				phase.DNSP95, phase.ConnectP95, phase.TLSP95, phase.FirstByteP95, phase.TotalP95)
		}
		for _, failure := range cell.Failures {
			fmt.Fprintf(&output, "\nFailure: %s\n", failure)
		}
	}
	return output.String()
}

func writeCapacityPoint(output *strings.Builder, label string, point *capacityPoint) {
	if point == nil {
		fmt.Fprintf(output, "%s: not established.\n\n", label)
		return
	}
	fmt.Fprintf(output, "%s: **%d routes, %d fresh connections/s, %d held streams** (%d/%d repetitions passed).\n\n",
		label, point.Routes, point.FreshRate, point.HeldStreams, point.Passed, point.Repetitions)
}
