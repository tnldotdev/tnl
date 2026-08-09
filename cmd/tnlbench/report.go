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
	SchemaVersion            int                      `json:"schema_version"`
	GeneratedAt              time.Time                `json:"generated_at"`
	Status                   string                   `json:"status"`
	ResultRows               int                      `json:"result_rows"`
	PassedRows               int                      `json:"passed_rows"`
	FailedRows               int                      `json:"failed_rows"`
	ProfileID                string                   `json:"profile_id,omitempty"`
	Region                   string                   `json:"region,omitempty"`
	Topology                 benchmarkTopology        `json:"topology,omitempty"`
	Machines                 benchmarkMachines        `json:"machines,omitempty"`
	ManagedPostgres          benchmarkManagedPostgres `json:"managed_postgres,omitempty"`
	CertificateAuthority     string                   `json:"certificate_authority,omitempty"`
	ExpectedSpendUSD         float64                  `json:"expected_spend_usd,omitempty"`
	MaximumSpendUSD          float64                  `json:"maximum_spend_usd,omitempty"`
	Cells                    []cellReport             `json:"cells"`
	HighestPassing           *capacityPoint           `json:"highest_passing,omitempty"`
	HighestRepeatablyPassing *capacityPoint           `json:"highest_repeatably_passing,omitempty"`
	FirstSaturation          *capacityPoint           `json:"first_saturation,omitempty"`
	CapacityRamps            []capacityRamp           `json:"capacity_ramps,omitempty"`
}

type cellReport struct {
	CellID             string                 `json:"cell_id"`
	Target             string                 `json:"target"`
	Suite              string                 `json:"suite"`
	Axis               string                 `json:"axis"`
	Sequence           int                    `json:"sequence"`
	Repetition         int                    `json:"repetition"`
	Status             string                 `json:"status"`
	ResultRows         int                    `json:"result_rows"`
	PublisherWorkers   int                    `json:"publisher_workers"`
	LoadWorkers        int                    `json:"load_workers"`
	Routes             int                    `json:"routes"`
	FreshRate          int                    `json:"fresh_connections_per_second"`
	HeldStreams        int                    `json:"held_streams"`
	LifecycleChurn     int                    `json:"lifecycle_churn_per_second"`
	PayloadBytes       int                    `json:"payload_bytes"`
	BandwidthBPS       float64                `json:"bandwidth_bytes_per_second,omitempty"`
	MonthlyCostUSD     float64                `json:"estimated_monthly_cost_usd,omitempty"`
	CapacityPerDollar  float64                `json:"capacity_per_monthly_dollar,omitempty"`
	Bottleneck         string                 `json:"bottleneck"`
	BottleneckEvidence []string               `json:"bottleneck_evidence,omitempty"`
	Recovery           *recoveryReport        `json:"recovery,omitempty"`
	Phases             map[string]phaseReport `json:"phases"`
	ResourceMaximums   map[string]float64     `json:"resource_maximums,omitempty"`
	Failures           []string               `json:"failures"`
}

type phaseReport struct {
	DurationMilliseconds float64 `json:"duration_milliseconds"`
	Attempts             int     `json:"attempts"`
	Successes            int     `json:"successes"`
	Errors               int     `json:"errors"`
	Bytes                int64   `json:"bytes"`
	AchievedRate         float64 `json:"achieved_rate,omitempty"`
	Concurrency          int     `json:"concurrency,omitempty"`
	DNSP95               float64 `json:"dns_p95_milliseconds,omitempty"`
	ConnectP95           float64 `json:"connect_p95_milliseconds,omitempty"`
	TLSP95               float64 `json:"tls_p95_milliseconds,omitempty"`
	FirstByteP50         float64 `json:"first_byte_p50_milliseconds,omitempty"`
	FirstByteP95         float64 `json:"first_byte_p95_milliseconds,omitempty"`
	TotalP50             float64 `json:"total_p50_milliseconds,omitempty"`
	TotalP95             float64 `json:"total_p95_milliseconds,omitempty"`
	TotalMaximum         float64 `json:"total_maximum_milliseconds,omitempty"`
}

type recoveryReport struct {
	Workers              int     `json:"workers"`
	RecoveredWorkers     int     `json:"recovered_workers"`
	Attempts             int     `json:"attempts"`
	Errors               int     `json:"errors"`
	DurationMilliseconds float64 `json:"duration_milliseconds"`
}

type capacityPoint struct {
	Target            string          `json:"target"`
	Axis              string          `json:"axis"`
	Sequence          int             `json:"sequence"`
	Routes            int             `json:"routes"`
	FreshRate         int             `json:"fresh_connections_per_second"`
	HeldStreams       int             `json:"held_streams"`
	LifecycleChurn    int             `json:"lifecycle_churn_per_second"`
	PayloadBytes      int             `json:"payload_bytes"`
	CapacityValue     float64         `json:"capacity_value"`
	CapacityUnit      string          `json:"capacity_unit"`
	MonthlyCostUSD    float64         `json:"estimated_monthly_cost_usd,omitempty"`
	CapacityPerDollar float64         `json:"capacity_per_monthly_dollar,omitempty"`
	Recovery          *recoveryReport `json:"recovery,omitempty"`
	Repetitions       int             `json:"repetitions"`
	Passed            int             `json:"passed"`
}

type capacityRamp struct {
	Axis                  string         `json:"axis"`
	LastPassing           *capacityPoint `json:"last_passing,omitempty"`
	LastRepeatablyPassing *capacityPoint `json:"last_repeatably_passing,omitempty"`
	FirstFailing          *capacityPoint `json:"first_failing,omitempty"`
}

type phaseAccumulator struct {
	workers, attempts, successes, errors, concurrency int
	bytes                                             int64
	achievedRate, durationMilliseconds                float64
	dns, connect, handshake                           *durationHistogram
	firstByte, total                                  *durationHistogram
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
	var plan benchmarkPlan
	if err := decodeJSONFile(filepath.Join(c.RunDirectory, "plan.json"), &plan); err == nil {
		if err := applyPlanToReport(&report, plan); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read benchmark plan: %w", err)
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
		!validBenchmarkAxis(result.Configuration.Axis) || result.Configuration.PayloadBytes <= 0 ||
		(result.Status != "passed" && result.Status != "failed") ||
		(result.Worker.Kind != "publisher" && result.Worker.Kind != "load") || result.Worker.Count <= 0 ||
		result.Worker.Index < 0 || result.Worker.Index >= result.Worker.Count || result.Configuration.Sequence < 0 ||
		result.Configuration.Routes <= 0 {
		return errors.New("invalid result schema or identity")
	}
	return nil
}

func buildReport(results []benchmarkResult) (benchmarkReport, error) {
	report := benchmarkReport{SchemaVersion: 3, GeneratedAt: time.Now().UTC(), Status: "passed", ResultRows: len(results)}
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
	summarizeReportCapacity(&report)
	return report, nil
}

func applyPlanToReport(report *benchmarkReport, plan benchmarkPlan) error {
	if plan.SchemaVersion != 3 || plan.ProfileID == "" || plan.Region == "" || plan.Suite == "" {
		return errors.New("benchmark plan identity is invalid")
	}
	report.ProfileID, report.Region = plan.ProfileID, plan.Region
	report.Topology, report.Machines, report.ManagedPostgres = plan.Topology, plan.Machines, plan.ManagedPostgres
	report.CertificateAuthority = plan.CertificateAuthority
	report.ExpectedSpendUSD, report.MaximumSpendUSD = plan.ExpectedSpendUSD, plan.MaximumSpendUSD
	byID := make(map[string]planCell, len(plan.Cells))
	for _, cell := range plan.Cells {
		byID[cell.ID] = cell
	}
	for index := range report.Cells {
		cell := &report.Cells[index]
		planned, found := byID[cell.CellID]
		if !found || cell.Suite != plan.Suite || planned.Axis != cell.Axis || planned.Sequence != cell.Sequence ||
			planned.Repetition != cell.Repetition || planned.Routes != cell.Routes ||
			planned.FreshConnectionsPerSecond != cell.FreshRate || planned.HeldStreams != cell.HeldStreams ||
			planned.LifecycleChurnPerSecond != cell.LifecycleChurn || planned.PayloadBytes != cell.PayloadBytes ||
			planned.EstimatedMonthlyCostUSD <= 0 {
			return fmt.Errorf("benchmark plan does not match result cell %q", cell.CellID)
		}
		cell.MonthlyCostUSD = planned.EstimatedMonthlyCostUSD
		value, _ := capacityValue(*cell)
		if cell.MonthlyCostUSD > 0 {
			cell.CapacityPerDollar = value / cell.MonthlyCostUSD
		}
	}
	summarizeReportCapacity(report)
	return nil
}

func summarizeReportCapacity(report *benchmarkReport) {
	report.CapacityRamps = capacityRamps(report.Cells)
	report.HighestPassing, report.HighestRepeatablyPassing, report.FirstSaturation = nil, nil, nil
	if len(report.CapacityRamps) == 1 {
		report.HighestPassing, report.HighestRepeatablyPassing, report.FirstSaturation = capacitySummary(report.Cells)
	}
}

func buildCellReport(cellID string, rows []benchmarkResult) (cellReport, error) {
	first := rows[0]
	cell := cellReport{
		CellID: cellID, Target: strings.TrimSuffix(cellID, fmt.Sprintf("-rep%d", first.Repetition)), Suite: first.Suite,
		Axis: first.Configuration.Axis, Sequence: first.Configuration.Sequence, Repetition: first.Repetition,
		Status: "passed", ResultRows: len(rows), Routes: first.Configuration.Routes,
		LifecycleChurn: first.Configuration.LifecycleChurnPerSecond,
		PayloadBytes:   first.Configuration.PayloadBytes, Phases: make(map[string]phaseReport),
		FreshRate: first.Configuration.FreshConnectionsPerSecond, HeldStreams: first.Configuration.HeldStreams,
		ResourceMaximums: make(map[string]float64), Failures: []string{}, Bottleneck: "not saturated",
	}
	seen := make(map[string]struct{})
	want := make(map[string]int)
	phases := make(map[string]*phaseAccumulator)
	var resourceSamples []resourceSample
	for _, row := range rows {
		if row.Suite != cell.Suite || row.Repetition != cell.Repetition || row.Configuration.Axis != cell.Axis ||
			row.Configuration.Sequence != cell.Sequence ||
			row.Configuration.Routes != cell.Routes || row.Configuration.FreshConnectionsPerSecond != cell.FreshRate ||
			row.Configuration.HeldStreams != cell.HeldStreams ||
			row.Configuration.LifecycleChurnPerSecond != cell.LifecycleChurn || row.Configuration.PayloadBytes != cell.PayloadBytes {
			return cellReport{}, fmt.Errorf("cell %q has inconsistent result configuration", cellID)
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
			accumulator.workers++
			accumulator.attempts += phase.Attempts
			accumulator.successes += phase.Successes
			accumulator.errors += phase.Errors
			accumulator.bytes += phase.Bytes
			accumulator.achievedRate += phase.AchievedRate
			accumulator.durationMilliseconds = max(accumulator.durationMilliseconds, phase.DurationMilliseconds)
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
	addDerivedResourceMaximums(cell.ResourceMaximums, resourceSamples)
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
			DurationMilliseconds: phase.durationMilliseconds,
			Attempts:             phase.attempts, Successes: phase.successes, Errors: phase.errors, Bytes: phase.bytes,
			AchievedRate: phase.achievedRate, Concurrency: phase.concurrency,
			DNSP95: histogramPercentile(phase.dns, 95), ConnectP95: histogramPercentile(phase.connect, 95),
			TLSP95: histogramPercentile(phase.handshake, 95), FirstByteP50: histogramPercentile(phase.firstByte, 50),
			FirstByteP95: histogramPercentile(phase.firstByte, 95), TotalP50: histogramPercentile(phase.total, 50),
			TotalP95: histogramPercentile(phase.total, 95), TotalMaximum: histogramMaximum(phase.total),
		}
	}
	if recovery, found := phases["recovery"]; found {
		cell.Recovery = &recoveryReport{
			Workers: recovery.workers, RecoveredWorkers: recovery.successes,
			Attempts: recovery.attempts, Errors: recovery.errors, DurationMilliseconds: recovery.durationMilliseconds,
		}
	}
	if fresh, found := cell.Phases["fresh"]; found && fresh.DurationMilliseconds > 0 {
		cell.BandwidthBPS = float64(fresh.Bytes) * 1000 / fresh.DurationMilliseconds
	}
	cell.BottleneckEvidence = resourceBottleneckEvidence(resourceSamples, cell.ResourceMaximums)
	if bottleneck, found := bottleneckFromEvidence(cell.BottleneckEvidence); cell.Status != "passed" && found {
		cell.Bottleneck = bottleneck
	} else if cell.Status != "passed" && len(cell.Failures) != 0 {
		cell.Bottleneck = classifyBenchmarkFailure(cell.Failures[0])
	} else if churn, found := cell.Phases["lifecycle_churn"]; found && churn.AchievedRate+0.01 < float64(cell.LifecycleChurn) {
		cell.Bottleneck = "publisher lifecycle churn"
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
		if strings.HasPrefix(sample.Moment, "load-") {
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

func addDerivedResourceMaximums(maximums map[string]float64, samples []resourceSample) {
	byIdentity := make(map[string][]resourceSample)
	for _, sample := range samples {
		if sample.Error == "" {
			byIdentity[sample.Identity] = append(byIdentity[sample.Identity], sample)
		}
	}
	for _, identitySamples := range byIdentity {
		sort.Slice(identitySamples, func(i, j int) bool {
			return identitySamples[i].Timestamp.Before(identitySamples[j].Timestamp)
		})
		for index := 1; index < len(identitySamples); index++ {
			previous, current := identitySamples[index-1], identitySamples[index]
			previousCPU, previousOK := previous.Metrics["process_cpu_seconds_total"]
			currentCPU, currentOK := current.Metrics["process_cpu_seconds_total"]
			elapsed := current.Timestamp.Sub(previous.Timestamp).Seconds()
			if !previousOK || !currentOK || currentCPU < previousCPU || elapsed <= 0 {
				continue
			}
			key := current.Role + "/process_cpu_cores"
			maximums[key] = max(maximums[key], (currentCPU-previousCPU)/elapsed)
		}
	}
}

func resourceBottleneckEvidence(samples []resourceSample, maximums map[string]float64) []string {
	type snapshot struct {
		role   string
		ready  map[string]float64
		loaded map[string]float64
	}
	byIdentity := make(map[string]*snapshot)
	for _, sample := range samples {
		if sample.Error != "" || (sample.Moment != "ready" && sample.Moment != "loaded") {
			continue
		}
		current := byIdentity[sample.Identity]
		if current == nil {
			current = &snapshot{role: sample.Role}
			byIdentity[sample.Identity] = current
		}
		if sample.Moment == "ready" {
			current.ready = sample.Metrics
		} else {
			current.loaded = sample.Metrics
		}
	}
	totals := make(map[string]float64)
	for _, values := range byIdentity {
		for name, loaded := range values.loaded {
			if metricBaseName(name) != "tnl_capacity_rejections_total" || loaded <= values.ready[name] {
				continue
			}
			resource := metricLabel(name, "resource")
			if resource == "" {
				resource = "unknown"
			}
			totals[values.role+"/"+resource] += loaded - values.ready[name]
		}
	}
	keys := make([]string, 0, len(totals))
	for key := range totals {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	evidence := make([]string, 0, len(keys)+1)
	for _, key := range keys {
		parts := strings.SplitN(key, "/", 2)
		evidence = append(evidence, fmt.Sprintf("%s %s capacity rejections increased by %g", parts[0], parts[1], totals[key]))
	}
	var peakKey string
	for key, value := range maximums {
		if strings.HasSuffix(key, "/process_cpu_cores") && (peakKey == "" || value > maximums[peakKey]) {
			peakKey = key
		}
	}
	if peakKey != "" {
		evidence = append(evidence, fmt.Sprintf("peak %s was %.2f cores", strings.TrimSuffix(peakKey, "/process_cpu_cores"), maximums[peakKey]))
	}
	return evidence
}

func metricBaseName(name string) string {
	if index := strings.IndexByte(name, '{'); index >= 0 {
		return name[:index]
	}
	return name
}

func metricLabel(name, label string) string {
	marker := label + "=\""
	start := strings.Index(name, marker)
	if start < 0 {
		return ""
	}
	value := name[start+len(marker):]
	if end := strings.IndexByte(value, '"'); end >= 0 {
		return value[:end]
	}
	return ""
}

func bottleneckFromEvidence(evidence []string) (string, bool) {
	for _, item := range evidence {
		fields := strings.Fields(item)
		if len(fields) >= 3 && fields[2] == "capacity" {
			return fields[0] + " " + strings.ReplaceAll(fields[1], "_", " ") + " capacity", true
		}
	}
	return "", false
}

func classifyBenchmarkFailure(failure string) string {
	lower := strings.ToLower(failure)
	switch {
	case strings.Contains(lower, "lifecycle churn"):
		return "publisher lifecycle churn"
	case strings.Contains(lower, "held stream"):
		return "held visitor streams"
	case strings.Contains(lower, "fresh visitor"):
		return "fresh visitor throughput"
	case strings.Contains(lower, "source limiter"):
		return "ingress source limiter"
	case strings.Contains(lower, "metrics"):
		return "benchmark instrumentation"
	default:
		return "worker failure"
	}
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
			created := capacityPointFromCell(cell)
			point = &created
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

func capacityRamps(cells []cellReport) []capacityRamp {
	byAxis := make(map[string][]cellReport)
	for _, cell := range cells {
		byAxis[cell.Axis] = append(byAxis[cell.Axis], cell)
	}
	axes := make([]string, 0, len(byAxis))
	for axis := range byAxis {
		axes = append(axes, axis)
	}
	sort.Strings(axes)
	result := make([]capacityRamp, 0, len(axes))
	for _, axis := range axes {
		highest, repeatable, saturation := capacitySummary(byAxis[axis])
		result = append(result, capacityRamp{
			Axis: axis, LastPassing: highest, LastRepeatablyPassing: repeatable, FirstFailing: saturation,
		})
	}
	return result
}

func capacityPointFromCell(cell cellReport) capacityPoint {
	value, unit := capacityValue(cell)
	perDollar := float64(0)
	if cell.MonthlyCostUSD > 0 {
		perDollar = value / cell.MonthlyCostUSD
	}
	return capacityPoint{
		Target: cell.Target, Axis: cell.Axis, Sequence: cell.Sequence, Routes: cell.Routes,
		FreshRate: cell.FreshRate, HeldStreams: cell.HeldStreams,
		LifecycleChurn: cell.LifecycleChurn, PayloadBytes: cell.PayloadBytes,
		CapacityValue: value, CapacityUnit: unit, MonthlyCostUSD: cell.MonthlyCostUSD, CapacityPerDollar: perDollar,
		Recovery: cell.Recovery,
	}
}

func capacityValue(cell cellReport) (float64, string) {
	switch cell.Axis {
	case "lifecycle_churn":
		if phase, found := cell.Phases["lifecycle_churn"]; found {
			return phase.AchievedRate, "route sessions/s"
		}
		return float64(cell.LifecycleChurn), "route sessions/s"
	case "fresh_connections":
		if phase, found := cell.Phases["fresh"]; found {
			return phase.AchievedRate, "connections/s"
		}
		return float64(cell.FreshRate), "connections/s"
	case "held_streams":
		return float64(cell.HeldStreams), "streams"
	case "bandwidth":
		return cell.BandwidthBPS, "bytes/s"
	default:
		return float64(cell.Routes), "routes"
	}
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
	if report.ProfileID != "" {
		fmt.Fprintf(&output, "Profile: `%s` in `%s`; %d control, %d ingress, %dx%d relay processes; certificates: %s.\n\n",
			report.ProfileID, report.Region, report.Topology.ControlProcesses, report.Topology.IngressProcesses,
			report.Topology.RelayServices, report.Topology.RelayProcessesPerService, report.CertificateAuthority)
		fmt.Fprintf(&output, "Campaign spend estimate: **$%.4f expected, $%.4f maximum**.\n\n",
			report.ExpectedSpendUSD, report.MaximumSpendUSD)
	}
	if len(report.CapacityRamps) == 1 {
		writeCapacityPoint(&output, "Highest passing cell", report.HighestPassing)
		writeCapacityPoint(&output, "Highest repeatably passing cell", report.HighestRepeatablyPassing)
		writeCapacityPoint(&output, "First saturation point", report.FirstSaturation)
	}
	if len(report.CapacityRamps) != 0 {
		output.WriteString("## Ramp Boundaries\n\n")
		for _, ramp := range report.CapacityRamps {
			fmt.Fprintf(&output, "### %s\n\n", ramp.Axis)
			writeCapacityPoint(&output, "Last passing target", ramp.LastPassing)
			writeCapacityPoint(&output, "Last repeatably passing target", ramp.LastRepeatablyPassing)
			writeCapacityPoint(&output, "First failing target", ramp.FirstFailing)
		}
	}
	output.WriteString("\nThese are observed benchmark boundaries, not product SLOs.\n\n")
	output.WriteString("| Cell | Axis | Status | Routes | Churn/s | Fresh/s | Held | Payload | MiB/s | Monthly | Capacity/$ | Recovery | Bottleneck |\n")
	output.WriteString("| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |\n")
	for _, cell := range report.Cells {
		fmt.Fprintf(&output, "| %s | %s | %s | %d | %d | %d | %d | %d | %.2f | $%.2f | %.4f | %s | %s |\n",
			cell.CellID, cell.Axis, cell.Status, cell.Routes, cell.LifecycleChurn, cell.FreshRate,
			cell.HeldStreams, cell.PayloadBytes, cell.BandwidthBPS/(1<<20), cell.MonthlyCostUSD,
			cell.CapacityPerDollar, formatRecovery(cell.Recovery), cell.Bottleneck)
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
		for _, evidence := range cell.BottleneckEvidence {
			fmt.Fprintf(&output, "\nBottleneck evidence: %s.\n", evidence)
		}
	}
	return output.String()
}

func writeCapacityPoint(output *strings.Builder, label string, point *capacityPoint) {
	if point == nil {
		fmt.Fprintf(output, "%s: not established.\n\n", label)
		return
	}
	fmt.Fprintf(output, "%s: **%.2f %s** (%d routes, %d churn/s, %d fresh/s, %d held, %d-byte payload; %d/%d repetitions passed",
		label, point.CapacityValue, point.CapacityUnit, point.Routes, point.LifecycleChurn,
		point.FreshRate, point.HeldStreams, point.PayloadBytes, point.Passed, point.Repetitions)
	if point.MonthlyCostUSD > 0 {
		fmt.Fprintf(output, "; $%.2f/month, %.4f %s per monthly dollar", point.MonthlyCostUSD, point.CapacityPerDollar, point.CapacityUnit)
	}
	if point.Recovery != nil {
		fmt.Fprintf(output, "; recovery %s", formatRecovery(point.Recovery))
	}
	output.WriteString(").\n\n")
}

func formatRecovery(recovery *recoveryReport) string {
	if recovery == nil {
		return "not triggered"
	}
	if recovery.RecoveredWorkers != recovery.Workers {
		return fmt.Sprintf("not recovered (%d/%d)", recovery.RecoveredWorkers, recovery.Workers)
	}
	return fmt.Sprintf("%.0f ms (%d/%d)", recovery.DurationMilliseconds, recovery.RecoveredWorkers, recovery.Workers)
}
