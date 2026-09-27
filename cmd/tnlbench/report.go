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

	dto "github.com/prometheus/client_model/go"
	"github.com/tnldotdev/tnl/internal/benchworkload"
	"github.com/tnldotdev/tnl/internal/observability"
)

type reportCommand struct {
	RunDirectory    string `name:"run" env:"BENCH_RUN" type:"path" required:"" help:"Benchmark run directory."`
	allowIncomplete bool
}

var errNoBenchmarkResults = errors.New("no benchmark result rows")

type benchmarkReport struct {
	TargetID              string                  `json:"target_id"`
	PublisherWorkers      int                     `json:"publisher_workers"`
	LoadWorkers           int                     `json:"load_workers"`
	SchemaVersion         int                     `json:"schema_version"`
	GeneratedAt           time.Time               `json:"generated_at"`
	Status                string                  `json:"status"`
	VisitorStatus         string                  `json:"visitor_status"`
	ShutdownStatus        string                  `json:"shutdown_status"`
	InfrastructureCleanup string                  `json:"infrastructure_cleanup"`
	Incomplete            bool                    `json:"incomplete"`
	Plan                  *benchmarkPlan          `json:"plan,omitempty"`
	ResultRows            int                     `json:"result_rows"`
	Phases                map[string]phaseResult  `json:"phases"`
	ServerDurations       []processDurationReport `json:"server_durations"`
	DatabaseDiagnostics   []databaseDiagnostic    `json:"database_diagnostics,omitempty"`
	Failures              []string                `json:"failures"`
}
type processDurationReport struct {
	Role      string                          `json:"role"`
	Identity  string                          `json:"identity"`
	Phase     string                          `json:"phase"`
	StartedAt time.Time                       `json:"started_at"`
	EndedAt   time.Time                       `json:"ended_at"`
	Complete  bool                            `json:"complete"`
	Error     string                          `json:"error,omitempty"`
	Durations []observability.DurationSummary `json:"durations"`
}

func (c reportCommand) run(stdout io.Writer) error {
	rows, err := readBenchmarkResults(filepath.Join(c.RunDirectory, "results.jsonl"))
	if err != nil && !(c.allowIncomplete && (errors.Is(err, os.ErrNotExist) || errors.Is(err, errNoBenchmarkResults))) {
		return err
	}
	report, err := buildReport(rows)
	if err != nil {
		return err
	}
	var plan benchmarkPlan
	if err := decodeJSONFile(filepath.Join(c.RunDirectory, "plan.json"), &plan); err != nil {
		return err
	}
	if err := applyPlanToReport(&report, plan); err != nil {
		return err
	}
	manifest, err := loadManifest(filepath.Join(c.RunDirectory, "manifest.json"))
	if err != nil {
		return err
	}
	report.InfrastructureCleanup = manifest.Status
	if manifest.Status != "cleaned" || c.allowIncomplete {
		report.Status = "failed"
	}
	if err := writeIndentedJSON(filepath.Join(c.RunDirectory, "report.json"), report); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(c.RunDirectory, "report.md"), []byte(formatReportMarkdown(report)), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Report: %s\n", filepath.Join(c.RunDirectory, "report.md"))
	return nil
}

func readBenchmarkResults(path string) ([]benchmarkResult, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var rows []benchmarkResult
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 16<<20)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var row benchmarkResult
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return nil, err
		}
		if err := validateResultIdentity(row); err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, errNoBenchmarkResults
	}
	return rows, nil
}

func validateResultIdentity(row benchmarkResult) error {
	if row.SchemaVersion != benchmarkResultSchemaVersion || row.CellID == "" || (row.Status != "passed" && row.Status != "failed") || (row.Worker.Kind != "publisher" && row.Worker.Kind != "load") || row.Worker.Count < 1 || row.Worker.Index < 0 || row.Worker.Index >= row.Worker.Count {
		return errors.New("invalid result identity")
	}
	return nil
}

func buildReport(rows []benchmarkResult) (benchmarkReport, error) {
	r := benchmarkReport{SchemaVersion: 5, GeneratedAt: time.Now().UTC(), Status: "passed", VisitorStatus: "not_run", ShutdownStatus: "not_run", ResultRows: len(rows), Phases: make(map[string]phaseResult)}
	seen := make(map[string]bool)
	expected := make(map[string]int)
	counts := make(map[string]int)
	var target string
	for _, row := range rows {
		if err := validateResultIdentity(row); err != nil {
			return r, err
		}
		if target != "" && target != row.CellID {
			return r, errors.New("results contain multiple targets")
		}
		target = row.CellID
		key := fmt.Sprintf("%s-%d", row.Worker.Kind, row.Worker.Index)
		if seen[key] {
			return r, errors.New("duplicate worker result")
		}
		seen[key] = true
		if want := expected[row.Worker.Kind]; want != 0 && want != row.Worker.Count {
			return r, errors.New("inconsistent worker counts")
		}
		expected[row.Worker.Kind] = row.Worker.Count
		counts[row.Worker.Kind]++
		if row.Status != "passed" {
			r.Status = "failed"
			if row.Failure != nil {
				r.Failures = append(r.Failures, row.Failure.Message)
			}
		}
		if row.Worker.Kind == "load" {
			if r.VisitorStatus != "failed" {
				r.VisitorStatus = row.Status
			}
		}
		if row.Worker.Kind == "publisher" {
			if !row.Cleanup.Exact {
				r.ShutdownStatus = "failed"
			} else if r.ShutdownStatus != "failed" {
				r.ShutdownStatus = "passed"
			}
		}
		r.DatabaseDiagnostics = append(r.DatabaseDiagnostics, row.DatabaseDiagnostics...)
		r.ServerDurations = append(r.ServerDurations, serverDurationReports(row.Resources)...)
		for _, phase := range row.Phases {
			merged := r.Phases[phase.Name]
			merged.Name = phase.Name
			if merged.StartedAt.IsZero() || phase.StartedAt.Before(merged.StartedAt) {
				merged.StartedAt = phase.StartedAt
			}
			merged.DurationMilliseconds = max(merged.DurationMilliseconds, phase.DurationMilliseconds)
			merged.Attempts += phase.Attempts
			merged.Successes += phase.Successes
			merged.Errors += phase.Errors
			if err := mergeDurationHistogram(&merged.Total, phase.Total); err != nil {
				return r, err
			}
			if phase.Visitor != nil {
				if merged.Visitor == nil {
					merged.Visitor = new(benchworkload.VisitorResult)
				}
				if err := merged.Visitor.Merge(*phase.Visitor); err != nil {
					return r, err
				}
				if phase.Visitor.Err() != nil {
					r.Status = "failed"
					r.VisitorStatus = "failed"
				}
			}
			r.Phases[phase.Name] = merged
		}
	}
	for _, kind := range []string{"publisher", "load"} {
		if expected[kind] == 0 || counts[kind] != expected[kind] {
			r.Status = "failed"
			r.Incomplete = true
			r.Failures = append(r.Failures, fmt.Sprintf("missing %s results: %d/%d", kind, counts[kind], expected[kind]))
			if kind == "load" {
				r.VisitorStatus = "incomplete"
			} else {
				r.ShutdownStatus = "incomplete"
			}
		}
	}
	r.TargetID = target
	r.PublisherWorkers = expected["publisher"]
	r.LoadWorkers = expected["load"]
	return r, nil
}

func applyPlanToReport(r *benchmarkReport, p benchmarkPlan) error {
	if p.SchemaVersion != 4 || p.ProfileID == "" || p.Target.ID == "" {
		return errors.New("invalid report plan")
	}
	r.Plan = &p
	if r.TargetID != "" && r.TargetID != p.Target.ID {
		return errors.New("result target differs from plan")
	}
	if r.PublisherWorkers != p.Target.PublisherWorkers || r.LoadWorkers != p.Target.LoadWorkers {
		r.Status = "failed"
		r.Incomplete = true
	}
	if r.ResultRows != p.Target.PublisherWorkers+p.Target.LoadWorkers {
		r.Status = "failed"
		r.Incomplete = true
	}
	for repetition := 1; repetition <= p.Target.Repetitions; repetition++ {
		name := fmt.Sprintf("steady-%d", repetition)
		phase, found := r.Phases[name]
		if !found || phase.Visitor == nil || phase.Visitor.Workers != p.Target.Concurrency || phase.Visitor.QueueSlots != p.Target.QueueSlots || phase.Visitor.Rate != p.Target.FreshConnectionsPerSecond {
			r.Status = "failed"
			r.Incomplete = true
			r.Failures = append(r.Failures, "missing or inconsistent "+name+" visitor measurements")
		}
	}
	for _, interval := range r.ServerDurations {
		if !interval.Complete {
			r.Status = "failed"
			r.Failures = append(r.Failures, interval.Identity+": "+interval.Error)
		}
	}
	expectedProcesses := p.Topology.ControlProcesses + p.Topology.IngressProcesses + p.Topology.RelayServices*p.Topology.RelayProcessesPerService
	for repetition := 1; repetition <= p.Target.Repetitions; repetition++ {
		name := fmt.Sprintf("steady-%d", repetition)
		count := 0
		for _, interval := range r.ServerDurations {
			if interval.Phase == name {
				count++
			}
		}
		if count != expectedProcesses {
			r.Status = "failed"
			r.Incomplete = true
			r.Failures = append(r.Failures, "missing server metric intervals for "+name)
		}
	}
	return nil
}

// Keep process identities and measurement windows separate. A restart, missing
// scrape, or failed interval must not turn into an apparently zero latency.
func serverDurationReports(samples []resourceSample) []processDurationReport {
	type key struct{ role, identity, phase string }
	type boundaries struct {
		before, after *resourceSample
		duplicate     bool
	}
	groups := make(map[key]*boundaries)
	for i := range samples {
		s := &samples[i]
		phase, before := strings.CutSuffix(s.Moment, "-before")
		if !before {
			var ok bool
			phase, ok = strings.CutSuffix(s.Moment, "-after")
			if !ok {
				continue
			}
		}
		k := key{s.Role, s.Identity, phase}
		if groups[k] == nil {
			groups[k] = new(boundaries)
		}
		g := groups[k]
		if before {
			g.duplicate = g.duplicate || g.before != nil
			g.before = s
		} else {
			g.duplicate = g.duplicate || g.after != nil
			g.after = s
		}
	}
	var reports []processDurationReport
	for k, g := range groups {
		r := processDurationReport{Role: k.role, Identity: k.identity, Phase: k.phase}
		if g.before != nil {
			r.StartedAt = g.before.Timestamp
		}
		if g.after != nil {
			r.EndedAt = g.after.Timestamp
		}
		switch {
		case g.duplicate:
			r.Error = "duplicate boundary snapshots"
		case g.before == nil || g.after == nil:
			r.Error = "missing baseline or final snapshot"
		case g.before.Error != "" || g.after.Error != "":
			r.Error = "boundary scrape unavailable"
		case !r.EndedAt.After(r.StartedAt):
			r.Error = "final snapshot does not follow baseline"
		case len(g.before.Metrics) == 0 || len(g.after.Metrics) == 0:
			r.Error = "empty boundary scrape"
		default:
			var err error
			r.Durations, err = observability.DurationSummaries(g.before.Metrics, g.after.Metrics)
			if err != nil {
				r.Error = err.Error()
			} else {
				r.Complete = true
			}
		}
		reports = append(reports, r)
	}
	sort.Slice(reports, func(i, j int) bool {
		if reports[i].Identity != reports[j].Identity {
			return reports[i].Identity < reports[j].Identity
		}
		return reports[i].Phase < reports[j].Phase
	})
	return reports
}

func scalarMetric(families []*dto.MetricFamily, name string) (float64, bool) {
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		var total float64
		for _, metric := range family.Metric {
			switch {
			case metric.Counter != nil:
				total += metric.Counter.GetValue()
			case metric.Gauge != nil:
				total += metric.Gauge.GetValue()
			case metric.Untyped != nil:
				total += metric.Untyped.GetValue()
			}
		}
		return total, true
	}
	return 0, false
}

func formatReportMarkdown(r benchmarkReport) string {
	var out strings.Builder
	fmt.Fprintf(&out, "# Benchmark result\n\nStatus: **%s**. Visitors: %s. Publisher shutdown: %s. Infrastructure: %s.\n\n", r.Status, r.VisitorStatus, r.ShutdownStatus, r.InfrastructureCleanup)
	if r.Plan != nil {
		fmt.Fprintf(&out, "Target: %d public URLs, %d fresh requests/sec, %d concurrent, %d waiting; %d repeated windows.\n\n", r.Plan.Target.PublicURLs, r.Plan.Target.FreshConnectionsPerSecond, r.Plan.Target.Concurrency, r.Plan.Target.QueueSlots, r.Plan.Target.Repetitions)
	}
	names := make([]string, 0, len(r.Phases))
	for name := range r.Phases {
		names = append(names, name)
	}
	sort.Strings(names)
	fmt.Fprintln(&out, "| Phase | Offered | Successful | Failed | Missed | Queue expired | p95 total (ms) |\n| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
	for _, name := range names {
		p := r.Phases[name]
		if p.Visitor == nil {
			fmt.Fprintf(&out, "| %s | %d | %d | %d | - | - | %s |\n", name, p.Attempts, p.Successes, p.Errors, formatOptionalDuration(histogramPercentile(p.Total, 95), 1))
			continue
		}
		v := p.Visitor
		fmt.Fprintf(&out, "| %s | %d | %d | %d | %d | %d | %s |\n", name, v.Scheduled, v.Successes, v.Failures, v.Missed, v.QueueExpired, formatOptionalDuration(histogramPercentile(&v.Total, 95), 1))
	}
	fmt.Fprintln(&out, "\nLatencies are approximate histogram percentiles; worker bucket counts are merged before computing percentiles.")
	for _, process := range r.ServerDurations {
		fmt.Fprintf(&out, "## %s %s / %s\n\ncomplete: %t; %s\n\n", process.Role, process.Identity, process.Phase, process.Complete, process.Error)
		for _, d := range process.Durations {
			fmt.Fprintf(&out, "- %s %v: %d observations; p95 %s ms\n", d.Name, d.Labels, d.Count, formatOptionalDuration(d.P95Seconds, 1000))
		}
	}
	for _, failure := range r.Failures {
		fmt.Fprintf(&out, "\n- %s\n", failure)
	}
	return out.String()
}
func formatOptionalDuration(value *float64, scale float64) string {
	if value == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.3f", *value*scale)
}
