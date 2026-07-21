package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"text/tabwriter"
	"time"
)

const profileStaleAfter = 90 * 24 * time.Hour

type planCommand struct {
	Suite       string `name:"suite" env:"BENCH_SUITE" default:"smoke" help:"Named suite to expand: smoke, scout, or confirm."`
	ProfileFile string `name:"profile" env:"BENCH_PROFILE" default:"benchmarks/suites/fly-production.json" type:"path" help:"Production-candidate benchmark profile."`
	Routes      int    `name:"routes" env:"BENCH_ROUTES" help:"Route count overriding the suite; required for confirm."`
	FreshRate   int    `name:"fresh-connections-per-second" env:"BENCH_FRESH_CONNECTIONS_PER_SECOND" help:"Total fresh visitor connections per second overriding the suite; required for confirm."`
	HeldStreams int    `name:"held-streams" env:"BENCH_HELD_STREAMS" help:"Held-open visitor streams overriding the suite; required for confirm."`
	Repetitions int    `name:"repetitions" env:"BENCH_REPETITIONS" help:"Repetitions overriding the suite."`
	Format      string `name:"format" env:"BENCH_PLAN_FORMAT" enum:"human,json" default:"human" help:"Plan output format."`
}

type benchmarkProfile struct {
	SchemaVersion int                        `json:"schema_version"`
	ID            string                     `json:"id"`
	UpdatedDate   string                     `json:"updated_date"`
	Region        string                     `json:"region"`
	Topology      benchmarkTopology          `json:"topology"`
	Machines      benchmarkMachines          `json:"machines"`
	WorkerLimits  benchmarkWorkerLimits      `json:"worker_limits"`
	Pricing       benchmarkPricing           `json:"pricing"`
	Suites        map[string]suiteDefinition `json:"suites"`
}

type benchmarkTopology struct {
	ControlProcesses         int `json:"control_processes"`
	IngressProcesses         int `json:"ingress_processes"`
	RelayServices            int `json:"relay_services"`
	RelayProcessesPerService int `json:"relay_processes_per_service"`
}

type benchmarkMachines struct {
	Postgres    string `json:"postgres"`
	Control     string `json:"control"`
	Ingress     string `json:"ingress"`
	Relay       string `json:"relay"`
	Coordinator string `json:"coordinator"`
	Publisher   string `json:"publisher"`
	Load        string `json:"load"`
}

type benchmarkWorkerLimits struct {
	RoutesPerPublisher            int `json:"routes_per_publisher"`
	FreshConnectionsPerLoadSecond int `json:"fresh_connections_per_load_second"`
	HeldStreamsPerLoad            int `json:"held_streams_per_load"`
}

type benchmarkPricing struct {
	SnapshotDate         string             `json:"snapshot_date"`
	SourceURL            string             `json:"source_url"`
	Route53SourceURL     string             `json:"route53_source_url"`
	MachinePerSecondUSD  map[string]float64 `json:"machine_per_second_usd"`
	PublicIPv4PerHour    float64            `json:"public_ipv4_per_hour_usd"`
	VolumeGBPerMonth     float64            `json:"volume_gb_per_month_usd"`
	HostedZonePerMonth   float64            `json:"hosted_zone_per_month_usd"`
}

type suiteDefinition struct {
	Repetitions    int                 `json:"repetitions"`
	RequiresTarget bool                `json:"requires_target,omitempty"`
	Cells          []benchmarkCellSpec `json:"cells"`
}

type benchmarkCellSpec struct {
	Routes                    int `json:"routes"`
	FreshConnectionsPerSecond int `json:"fresh_connections_per_second"`
	HeldStreams               int `json:"held_streams"`
	WarmupSeconds             int `json:"warmup_seconds"`
	DurationSeconds           int `json:"duration_seconds"`
}

type benchmarkPlan struct {
	SchemaVersion           int               `json:"schema_version"`
	ReadOnly                bool              `json:"read_only"`
	ProfileID               string            `json:"profile_id"`
	Suite                   string            `json:"suite"`
	Region                  string            `json:"region"`
	Topology                benchmarkTopology `json:"topology"`
	Machines                benchmarkMachines `json:"machines"`
	Cells                   []planCell        `json:"cells"`
	ExpectedDurationSeconds int64             `json:"expected_duration_seconds"`
	MaximumDurationSeconds  int64             `json:"maximum_duration_seconds"`
	ExpectedResultRows      int               `json:"expected_result_rows"`
	ExpectedSpendUSD        float64           `json:"expected_spend_usd"`
	MaximumSpendUSD         float64           `json:"maximum_spend_usd"`
	PricingSnapshotDate     string            `json:"pricing_snapshot_date"`
	PricingSourceURL        string            `json:"pricing_source_url"`
	Route53PricingSourceURL string            `json:"route53_pricing_source_url"`
	RequiredInputs          []string          `json:"required_inputs"`
	Overrides               map[string]string `json:"overrides"`
	Warnings                []string          `json:"warnings"`
}

type planCell struct {
	ID                        string  `json:"id"`
	Sequence                  int     `json:"sequence"`
	Repetition                int     `json:"repetition"`
	Routes                    int     `json:"routes"`
	FreshConnectionsPerSecond int     `json:"fresh_connections_per_second"`
	HeldStreams               int     `json:"held_streams"`
	PublisherWorkers          int     `json:"publisher_workers"`
	LoadWorkers               int     `json:"load_workers"`
	FreshConnectionsPerWorker float64 `json:"fresh_connections_per_worker_second"`
	HeldStreamsPerWorker      int     `json:"held_streams_per_worker"`
	WarmupSeconds             int     `json:"warmup_seconds"`
	DurationSeconds           int     `json:"duration_seconds"`
	TimeoutSeconds            int     `json:"timeout_seconds"`
}

func (c planCommand) run(stdout io.Writer) error {
	plan, err := c.build(time.Now())
	if err != nil {
		return err
	}
	if c.Format == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(plan)
	}
	return writeHumanPlan(stdout, plan)
}

func (c planCommand) build(now time.Time) (benchmarkPlan, error) {
	var profile benchmarkProfile
	if err := decodeJSONFile(c.ProfileFile, &profile); err != nil {
		return benchmarkPlan{}, fmt.Errorf("benchmark profile: %w", err)
	}
	if err := validateBenchmarkProfile(profile); err != nil {
		return benchmarkPlan{}, err
	}
	definition, found := profile.Suites[c.Suite]
	if !found {
		return benchmarkPlan{}, fmt.Errorf("suite %q is not defined by profile %q", c.Suite, profile.ID)
	}
	overridingTarget := c.Routes != 0 || c.FreshRate != 0 || c.HeldStreams != 0
	if definition.RequiresTarget && (c.Routes == 0 || c.FreshRate == 0 || c.HeldStreams == 0) {
		return benchmarkPlan{}, errors.New("confirm requires BENCH_ROUTES, BENCH_FRESH_CONNECTIONS_PER_SECOND, and BENCH_HELD_STREAMS")
	}
	if overridingTarget {
		if c.Routes <= 0 || c.FreshRate <= 0 || c.HeldStreams < 0 {
			return benchmarkPlan{}, errors.New("route, fresh-connection, and held-stream overrides must be supplied together")
		}
		warmup, duration := 60, 300
		if len(definition.Cells) == 1 {
			warmup, duration = definition.Cells[0].WarmupSeconds, definition.Cells[0].DurationSeconds
		}
		definition.Cells = []benchmarkCellSpec{{
			Routes: c.Routes, FreshConnectionsPerSecond: c.FreshRate, HeldStreams: c.HeldStreams,
			WarmupSeconds: warmup, DurationSeconds: duration,
		}}
	}
	if c.Repetitions != 0 {
		definition.Repetitions = c.Repetitions
	}
	if definition.Repetitions < 1 || definition.Repetitions > 10 {
		return benchmarkPlan{}, errors.New("repetitions must be between 1 and 10")
	}

	plan := benchmarkPlan{
		SchemaVersion: 1, ReadOnly: true, ProfileID: profile.ID, Suite: c.Suite, Region: profile.Region,
		Topology: profile.Topology, Machines: profile.Machines,
		PricingSnapshotDate: profile.Pricing.SnapshotDate, PricingSourceURL: profile.Pricing.SourceURL,
		Route53PricingSourceURL: profile.Pricing.Route53SourceURL,
		RequiredInputs: []string{
			"Fly organization access through fly", "AWS credentials with Route 53 access",
			"an existing public Route 53 parent zone", "an ACME account email",
		},
		Overrides: configuredOverrides(),
		Warnings: []string{
			"Planning is read-only; execution creates paid Fly, IPv4, volume, and Route 53 resources.",
			"Spend is an estimate and excludes image builds, public egress, DNS queries, ACME, failed retries, and retained Fly resources.",
			"Maximum spend includes two full Route 53 hosted-zone charges if cleanup misses the 12-hour waiver.",
		},
	}
	updated, _ := time.Parse(time.DateOnly, profile.UpdatedDate)
	pricingDate, _ := time.Parse(time.DateOnly, profile.Pricing.SnapshotDate)
	if now.Sub(updated) > profileStaleAfter {
		plan.Warnings = append(plan.Warnings, "benchmark profile is more than 90 days old")
	}
	if now.Sub(pricingDate) > profileStaleAfter {
		plan.Warnings = append(plan.Warnings, "pricing snapshot is more than 90 days old")
	}
	for sequence, spec := range definition.Cells {
		if err := validateCellSpec(spec); err != nil {
			return benchmarkPlan{}, fmt.Errorf("suite %q: %w", c.Suite, err)
		}
		for repetition := 1; repetition <= definition.Repetitions; repetition++ {
			publishers := divideRoundUp(spec.Routes, profile.WorkerLimits.RoutesPerPublisher)
			loadWorkers := max(
				divideRoundUp(spec.FreshConnectionsPerSecond, profile.WorkerLimits.FreshConnectionsPerLoadSecond),
				divideRoundUp(spec.HeldStreams, profile.WorkerLimits.HeldStreamsPerLoad),
				1,
			)
			cell := planCell{
				ID:       fmt.Sprintf("%s-r%d-c%d-s%d-rep%d", c.Suite, spec.Routes, spec.FreshConnectionsPerSecond, spec.HeldStreams, repetition),
				Sequence: sequence, Repetition: repetition, Routes: spec.Routes,
				FreshConnectionsPerSecond: spec.FreshConnectionsPerSecond, HeldStreams: spec.HeldStreams,
				PublisherWorkers: publishers, LoadWorkers: loadWorkers,
				FreshConnectionsPerWorker: float64(spec.FreshConnectionsPerSecond) / float64(loadWorkers),
				HeldStreamsPerWorker:      divideRoundUp(spec.HeldStreams, loadWorkers),
				WarmupSeconds:             spec.WarmupSeconds, DurationSeconds: spec.DurationSeconds,
				TimeoutSeconds: spec.WarmupSeconds + spec.DurationSeconds + 15*60,
			}
			plan.Cells = append(plan.Cells, cell)
			plan.ExpectedDurationSeconds += int64(spec.WarmupSeconds + spec.DurationSeconds + 4*60)
			plan.MaximumDurationSeconds += int64(cell.TimeoutSeconds)
			plan.ExpectedResultRows += publishers + loadWorkers
			plan.ExpectedSpendUSD += estimatedCellSpend(profile, cell, spec.WarmupSeconds+spec.DurationSeconds+4*60)
			plan.MaximumSpendUSD += estimatedCellSpend(profile, cell, cell.TimeoutSeconds)
		}
	}
	// One PostgreSQL volume, five public app IPv4s, and two transient hosted zones.
	plan.ExpectedSpendUSD += fixedResourceSpend(profile, plan.ExpectedDurationSeconds, false)
	plan.MaximumSpendUSD += fixedResourceSpend(profile, plan.MaximumDurationSeconds, true)
	return plan, nil
}

func decodeJSONFile(path string, destination any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func validateBenchmarkProfile(profile benchmarkProfile) error {
	if profile.SchemaVersion != 1 || profile.ID == "" || profile.Region == "" {
		return errors.New("benchmark profile has an invalid schema or identity")
	}
	for label, value := range map[string]string{"updated_date": profile.UpdatedDate, "pricing snapshot_date": profile.Pricing.SnapshotDate} {
		if _, err := time.Parse(time.DateOnly, value); err != nil {
			return fmt.Errorf("%s must use YYYY-MM-DD", label)
		}
	}
	if profile.Topology != (benchmarkTopology{ControlProcesses: 2, IngressProcesses: 2, RelayServices: 2, RelayProcessesPerService: 2}) {
		return errors.New("benchmark topology must be 2 control, 2 ingress, and 2 processes in each of 2 relay services")
	}
	if profile.WorkerLimits.RoutesPerPublisher <= 0 || profile.WorkerLimits.FreshConnectionsPerLoadSecond <= 0 ||
		profile.WorkerLimits.FreshConnectionsPerLoadSecond >= 40 || profile.WorkerLimits.HeldStreamsPerLoad <= 0 {
		return errors.New("benchmark worker limits are invalid or could exercise the ingress source limiter")
	}
	sizes := []string{
		profile.Machines.Postgres, profile.Machines.Control, profile.Machines.Ingress, profile.Machines.Relay,
		profile.Machines.Coordinator, profile.Machines.Publisher, profile.Machines.Load,
	}
	for _, size := range sizes {
		if size == "" || profile.Pricing.MachinePerSecondUSD[size] <= 0 {
			return fmt.Errorf("pricing is missing machine size %q", size)
		}
	}
	if profile.Pricing.SourceURL == "" || profile.Pricing.Route53SourceURL == "" || profile.Pricing.PublicIPv4PerHour < 0 ||
		profile.Pricing.VolumeGBPerMonth < 0 || profile.Pricing.HostedZonePerMonth < 0 {
		return errors.New("benchmark pricing is invalid")
	}
	for name, definition := range profile.Suites {
		if definition.Repetitions < 1 || definition.Repetitions > 10 || len(definition.Cells) == 0 && !definition.RequiresTarget {
			return fmt.Errorf("suite %q is invalid", name)
		}
		for _, cell := range definition.Cells {
			if err := validateCellSpec(cell); err != nil {
				return fmt.Errorf("suite %q: %w", name, err)
			}
		}
	}
	return nil
}

func validateCellSpec(cell benchmarkCellSpec) error {
	if cell.Routes <= 0 || cell.Routes > 10_000 || cell.FreshConnectionsPerSecond <= 0 ||
		cell.FreshConnectionsPerSecond > 10_000 || cell.HeldStreams < 0 || cell.HeldStreams > 100_000 ||
		cell.WarmupSeconds < 0 || cell.DurationSeconds <= 0 {
		return fmt.Errorf("invalid cell r%d-c%d-s%d", cell.Routes, cell.FreshConnectionsPerSecond, cell.HeldStreams)
	}
	return nil
}

func divideRoundUp(value, divisor int) int {
	if value == 0 {
		return 0
	}
	return (value + divisor - 1) / divisor
}

func estimatedCellSpend(profile benchmarkProfile, cell planCell, seconds int) float64 {
	fixedRate := profile.Pricing.MachinePerSecondUSD[profile.Machines.Postgres] +
		float64(profile.Topology.ControlProcesses)*profile.Pricing.MachinePerSecondUSD[profile.Machines.Control] +
		float64(profile.Topology.IngressProcesses)*profile.Pricing.MachinePerSecondUSD[profile.Machines.Ingress] +
		float64(profile.Topology.RelayServices*profile.Topology.RelayProcessesPerService)*profile.Pricing.MachinePerSecondUSD[profile.Machines.Relay] +
		profile.Pricing.MachinePerSecondUSD[profile.Machines.Coordinator]
	workerRate := float64(cell.PublisherWorkers)*profile.Pricing.MachinePerSecondUSD[profile.Machines.Publisher] +
		float64(cell.LoadWorkers)*profile.Pricing.MachinePerSecondUSD[profile.Machines.Load]
	return (fixedRate + workerRate) * float64(seconds)
}

func fixedResourceSpend(profile benchmarkProfile, seconds int64, includeHostedZones bool) float64 {
	hours := float64(seconds) / 3600
	monthShare := float64(seconds) / (30 * 24 * 3600)
	spend := 5*profile.Pricing.PublicIPv4PerHour*hours + profile.Pricing.VolumeGBPerMonth*monthShare
	if includeHostedZones {
		spend += 2 * profile.Pricing.HostedZonePerMonth
	}
	return spend
}

func configuredOverrides() map[string]string {
	result := make(map[string]string)
	for _, name := range []string{
		"BENCH_SUITE", "BENCH_PROFILE", "BENCH_ROUTES", "BENCH_FRESH_CONNECTIONS_PER_SECOND",
		"BENCH_HELD_STREAMS", "BENCH_REPETITIONS",
	} {
		if value, found := os.LookupEnv(name); found {
			result[name] = value
		}
	}
	return result
}

func writeHumanPlan(destination io.Writer, plan benchmarkPlan) error {
	output := new(bytes.Buffer)
	fmt.Fprintln(output, "Benchmark plan (READ ONLY)")
	fmt.Fprintf(output, "Profile: %s  Suite: %s  Region: %s\n", plan.ProfileID, plan.Suite, plan.Region)
	fmt.Fprintf(output, "Topology: %d control, %d ingress, %dx%d relay processes\n\n",
		plan.Topology.ControlProcesses, plan.Topology.IngressProcesses,
		plan.Topology.RelayServices, plan.Topology.RelayProcessesPerService)
	table := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "CELL\tROUTES\tFRESH/S\tHELD\tPUBLISHERS\tLOAD\tFRESH/LOAD\tDURATION\tTIMEOUT")
	for _, cell := range plan.Cells {
		fmt.Fprintf(table, "%s\t%d\t%d\t%d\t%d\t%d\t%.1f\t%s\t%s\n",
			cell.ID, cell.Routes, cell.FreshConnectionsPerSecond, cell.HeldStreams,
			cell.PublisherWorkers, cell.LoadWorkers, cell.FreshConnectionsPerWorker,
			time.Duration(cell.DurationSeconds)*time.Second, time.Duration(cell.TimeoutSeconds)*time.Second)
	}
	if err := table.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(output, "\nTotals: %d cells, %d worker result rows, %s expected, %s maximum\n",
		len(plan.Cells), plan.ExpectedResultRows, time.Duration(plan.ExpectedDurationSeconds)*time.Second,
		time.Duration(plan.MaximumDurationSeconds)*time.Second)
	fmt.Fprintf(output, "Estimated spend: $%.4f expected, $%.4f maximum (USD)\n", plan.ExpectedSpendUSD, plan.MaximumSpendUSD)
	fmt.Fprintf(output, "Pricing: snapshot %s (%s; %s)\n", plan.PricingSnapshotDate, plan.PricingSourceURL, plan.Route53PricingSourceURL)
	fmt.Fprintln(output, "\nRequired inputs")
	for _, input := range plan.RequiredInputs {
		fmt.Fprintf(output, "- %s\n", input)
	}
	if len(plan.Overrides) != 0 {
		fmt.Fprintln(output, "\nOverrides")
		names := make([]string, 0, len(plan.Overrides))
		for name := range plan.Overrides {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintf(output, "- %s=%s\n", name, plan.Overrides[name])
		}
	}
	fmt.Fprintln(output, "\nWarnings")
	for _, warning := range plan.Warnings {
		fmt.Fprintf(output, "- %s\n", warning)
	}
	_, err := io.Copy(destination, output)
	return err
}
