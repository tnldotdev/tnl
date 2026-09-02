package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

const profileStaleAfter = 90 * 24 * time.Hour

type planCommand struct {
	Suite           string `name:"suite" env:"BENCH_SUITE" default:"smoke" help:"Named suite to expand."`
	ProfileFile     string `name:"profile" env:"BENCH_PROFILE" default:"benchmarks/suites/p1-horizontal.json" type:"path" help:"Benchmark suite profile."`
	WorkloadFile    string `name:"workload" env:"BENCH_WORKLOAD" default:"benchmarks/workloads/agent-worktrees-assumed-v1.json" type:"path" help:"Workload profile."`
	PricingFile     string `name:"pricing" env:"BENCH_PRICING" default:"benchmarks/pricing/fly-sjc.json" type:"path" help:"Pricing snapshot."`
	Workers         string `name:"workers" env:"BENCH_WORKERS" help:"Comma-separated worker counts overriding the suite."`
	RoutesPerWorker int    `name:"routes-per-worker" env:"BENCH_ROUTES_PER_WORKER" help:"Route density overriding the suite."`
	Repetitions     int    `name:"repetitions" env:"BENCH_REPETITIONS" help:"Repetitions overriding the suite."`
	Format          string `name:"format" env:"BENCH_PLAN_FORMAT" enum:"human,json" default:"human" help:"Plan output format."`
}

type workloadProfile struct {
	SchemaVersion  int               `json:"schema_version"`
	ID             string            `json:"id"`
	UpdatedDate    string            `json:"updated_date"`
	Classification string            `json:"classification"`
	Seed           uint64            `json:"seed"`
	Model          workloadModel     `json:"model"`
	Traffic        workloadTraffic   `json:"traffic"`
	Transport      workloadTransport `json:"transport"`
	Phases         []workloadPhase   `json:"phases"`
	ReferenceNotes []string          `json:"reference_notes"`
}

type workloadModel struct {
	ConcurrentRoutesPerActiveDeveloper int     `json:"concurrent_routes_per_active_developer"`
	PeakActiveShare                    float64 `json:"peak_active_share"`
	TrafficRouteShare                  float64 `json:"traffic_route_share"`
	IdleRouteShare                     float64 `json:"idle_route_share"`
	AverageRouteRestartIntervalSeconds int     `json:"average_route_restart_interval_seconds"`
	TypicalActiveSessionSeconds        int     `json:"typical_active_session_seconds"`
	ActiveWeekdaysPerMonth             int     `json:"active_weekdays_per_month"`
}

type workloadTraffic struct {
	PersistentStreamsPerBusyRoute      int     `json:"persistent_streams_per_busy_route"`
	FreshConnectionsPerBusyRouteMinute float64 `json:"fresh_connections_per_busy_route_per_minute"`
	TypicalResponseBytes               int     `json:"typical_response_bytes"`
	BurstConnectionsPerRoute           int     `json:"burst_connections_per_participating_route"`
	BurstResponseBytes                 int     `json:"burst_response_bytes"`
}

type workloadTransport struct {
	CapacityMode string  `json:"capacity_mode"`
	DERPShare    float64 `json:"derp_share"`
}

type workloadPhase struct {
	Name            string `json:"name"`
	DurationSeconds int    `json:"duration_seconds"`
	TimeoutSeconds  int    `json:"timeout_seconds"`
}

type suiteProfile struct {
	SchemaVersion      int                        `json:"schema_version"`
	ID                 string                     `json:"id"`
	UpdatedDate        string                     `json:"updated_date"`
	Workload           string                     `json:"workload"`
	Pricing            string                     `json:"pricing"`
	Region             string                     `json:"region"`
	Transport          string                     `json:"transport"`
	Machines           suiteMachines              `json:"machines"`
	HostedWorkerLimits workerLimits               `json:"hosted_worker_limits"`
	RequiredInputs     []string                   `json:"required_inputs"`
	Suites             map[string]suiteDefinition `json:"suites"`
}

type suiteMachines struct {
	Edge   edgeMachine   `json:"edge"`
	Worker workerMachine `json:"worker"`
	Driver driverMachine `json:"driver"`
}

type edgeMachine struct {
	Size  string `json:"size"`
	Count int    `json:"count"`
}

type workerMachine struct {
	Size     string `json:"size"`
	Capacity int    `json:"capacity"`
}

type driverMachine struct {
	Size string `json:"size"`
}

type workerLimits struct {
	Minimum int `json:"minimum"`
	Maximum int `json:"maximum"`
}

type suiteDefinition struct {
	Workers                  []int   `json:"workers"`
	TotalRoutes              []int   `json:"total_routes,omitempty"`
	RoutesPerWorker          int     `json:"routes_per_worker,omitempty"`
	Repetitions              int     `json:"repetitions"`
	RoutesPerDriver          int     `json:"routes_per_driver"`
	PhaseDurationScale       float64 `json:"phase_duration_scale"`
	RequiresSchedulingTarget bool    `json:"requires_scheduling_target,omitempty"`
}

type pricingProfile struct {
	SchemaVersion                  int                `json:"schema_version"`
	ID                             string             `json:"id"`
	SnapshotDate                   string             `json:"snapshot_date"`
	SourceURL                      string             `json:"source_url"`
	Region                         string             `json:"region"`
	Currency                       string             `json:"currency"`
	MachinePerSecond               map[string]float64 `json:"machine_per_second"`
	PublicEgressPerGB              float64            `json:"public_egress_per_gb"`
	VolumePerGBMonth               float64            `json:"volume_per_gb_month"`
	SnapshotPerGBMonth             float64            `json:"snapshot_per_gb_month"`
	SingleHostnameCertificateMonth float64            `json:"single_hostname_certificate_per_month"`
	WildcardCertificatePerMonth    float64            `json:"wildcard_certificate_per_month"`
	StoppedRootfsPerGBMonth        float64            `json:"stopped_rootfs_per_gb_month"`
	PerformanceReservationDiscount float64            `json:"performance_reservation_discount"`
	Notes                          []string           `json:"notes"`
}

type benchmarkPlan struct {
	SchemaVersion           int               `json:"schema_version"`
	ReadOnly                bool              `json:"read_only"`
	ProfileID               string            `json:"profile_id"`
	Suite                   string            `json:"suite"`
	Region                  string            `json:"region"`
	Transport               string            `json:"transport"`
	Workload                workloadProfile   `json:"workload"`
	Pricing                 planPricing       `json:"pricing"`
	Machines                suiteMachines     `json:"machines"`
	HostedWorkerLimits      workerLimits      `json:"hosted_worker_limits"`
	Cells                   []planCell        `json:"cells"`
	ExpectedDurationSeconds int64             `json:"expected_duration_seconds"`
	MaximumDurationSeconds  int64             `json:"maximum_duration_seconds"`
	ExpectedResultRows      int               `json:"expected_result_rows"`
	ExpectedSpend           planSpend         `json:"expected_spend"`
	MaximumSpend            planSpend         `json:"maximum_spend"`
	RequiredInputs          []string          `json:"required_inputs"`
	Dependencies            []string          `json:"dependencies"`
	Overrides               map[string]string `json:"overrides"`
	Warnings                []string          `json:"warnings"`
}

type planPricing struct {
	ID           string `json:"id"`
	SnapshotDate string `json:"snapshot_date"`
	SourceURL    string `json:"source_url"`
	Currency     string `json:"currency"`
}

type planCell struct {
	ID                      string  `json:"id"`
	Repetition              int     `json:"repetition"`
	Workers                 int     `json:"workers"`
	Routes                  int     `json:"routes"`
	RoutesPerWorker         float64 `json:"routes_per_worker"`
	Drivers                 int     `json:"drivers"`
	ExpectedDurationSeconds int64   `json:"expected_duration_seconds"`
	MaximumDurationSeconds  int64   `json:"maximum_duration_seconds"`
	ExpectedNetworkGB       float64 `json:"expected_network_gb"`
}

type planSpend struct {
	ComputeUSD      float64 `json:"compute_usd"`
	PublicEgressUSD float64 `json:"public_egress_usd"`
	TotalUSD        float64 `json:"total_usd"`
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
	writeHumanPlan(stdout, plan)
	return nil
}

func (c planCommand) build(now time.Time) (benchmarkPlan, error) {
	var profile suiteProfile
	if err := decodeProfile(c.ProfileFile, &profile); err != nil {
		return benchmarkPlan{}, fmt.Errorf("suite profile: %w", err)
	}
	var workload workloadProfile
	if err := decodeProfile(c.WorkloadFile, &workload); err != nil {
		return benchmarkPlan{}, fmt.Errorf("workload profile: %w", err)
	}
	var pricing pricingProfile
	if err := decodeProfile(c.PricingFile, &pricing); err != nil {
		return benchmarkPlan{}, fmt.Errorf("pricing profile: %w", err)
	}
	if err := validateProfiles(profile, workload, pricing); err != nil {
		return benchmarkPlan{}, err
	}
	definition, found := profile.Suites[c.Suite]
	if !found {
		return benchmarkPlan{}, fmt.Errorf("suite %q is not defined by profile %q", c.Suite, profile.ID)
	}
	if err := validateSuiteDefinition(c.Suite, definition, profile); err != nil {
		return benchmarkPlan{}, err
	}
	overrides := configuredOverrides()
	if c.Workers != "" {
		workers, err := parseWorkerCounts(c.Workers, profile.HostedWorkerLimits.Maximum)
		if err != nil {
			return benchmarkPlan{}, err
		}
		definition.Workers = workers
	}
	if c.RoutesPerWorker != 0 {
		definition.RoutesPerWorker = c.RoutesPerWorker
		definition.TotalRoutes = nil
	}
	if c.Repetitions != 0 {
		definition.Repetitions = c.Repetitions
	}
	if definition.Repetitions <= 0 || definition.Repetitions > 10 {
		return benchmarkPlan{}, errors.New("repetitions must be between 1 and 10")
	}
	if definition.RequiresSchedulingTarget && definition.RoutesPerWorker == 0 {
		return benchmarkPlan{}, fmt.Errorf("suite %q requires a qualified scheduling target via BENCH_ROUTES_PER_WORKER", c.Suite)
	}
	if definition.RoutesPerWorker > profile.Machines.Worker.Capacity {
		return benchmarkPlan{}, fmt.Errorf(
			"routes per worker %d exceeds configured worker capacity %d",
			definition.RoutesPerWorker, profile.Machines.Worker.Capacity,
		)
	}

	expectedSeconds, maximumSeconds := workloadDurations(workload, definition.PhaseDurationScale)
	cells, err := expandCells(c.Suite, definition, profile, workload, expectedSeconds, maximumSeconds)
	if err != nil {
		return benchmarkPlan{}, err
	}
	warnings := profileWarnings(now, profile, workload, pricing)
	warnings = append(warnings,
		"Spend estimates exclude image builds, failed-run retries, and external DNS or ACME services.",
		"Maximum network spend uses modeled traffic; only compute is extended to each cell timeout.",
	)
	plan := benchmarkPlan{
		SchemaVersion: 1, ReadOnly: true, ProfileID: profile.ID, Suite: c.Suite,
		Region: profile.Region, Transport: profile.Transport, Workload: workload,
		Pricing:  planPricing{ID: pricing.ID, SnapshotDate: pricing.SnapshotDate, SourceURL: pricing.SourceURL, Currency: pricing.Currency},
		Machines: profile.Machines, HostedWorkerLimits: profile.HostedWorkerLimits,
		Cells: cells, RequiredInputs: profile.RequiredInputs, Dependencies: []string{}, Overrides: overrides, Warnings: warnings,
	}
	for _, cell := range cells {
		plan.ExpectedDurationSeconds += cell.ExpectedDurationSeconds
		plan.MaximumDurationSeconds += cell.MaximumDurationSeconds
		plan.ExpectedResultRows += cell.Drivers
		rate := machineRate(pricing, profile.Machines.Edge.Size, profile.Machines.Edge.Count) +
			machineRate(pricing, profile.Machines.Worker.Size, cell.Workers) +
			machineRate(pricing, profile.Machines.Driver.Size, cell.Drivers)
		plan.ExpectedSpend.ComputeUSD += rate * float64(cell.ExpectedDurationSeconds)
		plan.MaximumSpend.ComputeUSD += rate * float64(cell.MaximumDurationSeconds)
		plan.ExpectedSpend.PublicEgressUSD += cell.ExpectedNetworkGB * pricing.PublicEgressPerGB
		plan.MaximumSpend.PublicEgressUSD += cell.ExpectedNetworkGB * pricing.PublicEgressPerGB
	}
	plan.ExpectedSpend.TotalUSD = plan.ExpectedSpend.ComputeUSD + plan.ExpectedSpend.PublicEgressUSD
	plan.MaximumSpend.TotalUSD = plan.MaximumSpend.ComputeUSD + plan.MaximumSpend.PublicEgressUSD
	return plan, nil
}

func decodeProfile(path string, destination any) error {
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

func validateProfiles(profile suiteProfile, workload workloadProfile, pricing pricingProfile) error {
	if profile.SchemaVersion != 1 || workload.SchemaVersion != 1 || pricing.SchemaVersion != 1 {
		return errors.New("profile schema_version must be 1")
	}
	if profile.ID == "" || workload.ID == "" || pricing.ID == "" {
		return errors.New("profile IDs must not be empty")
	}
	for label, value := range map[string]string{
		"suite updated_date":    profile.UpdatedDate,
		"workload updated_date": workload.UpdatedDate,
		"pricing snapshot_date": pricing.SnapshotDate,
	} {
		if _, err := time.Parse(time.DateOnly, value); err != nil {
			return fmt.Errorf("%s must use YYYY-MM-DD", label)
		}
	}
	if profile.Workload != workload.ID || profile.Pricing != pricing.ID {
		return errors.New("suite profile references do not match the loaded workload and pricing profiles")
	}
	if profile.Region == "" || profile.Region != pricing.Region {
		return errors.New("suite and pricing regions must match")
	}
	if profile.Transport != "forced-derp" && profile.Transport != "auto" {
		return fmt.Errorf("unsupported suite transport %q", profile.Transport)
	}
	if workload.Transport.CapacityMode != profile.Transport {
		return errors.New("suite transport does not match the workload capacity transport")
	}
	if profile.Transport == "forced-derp" && workload.Transport.DERPShare != 1 {
		return errors.New("forced DERP workloads must declare a DERP share of 1")
	}
	if workload.Classification != "assumed" && workload.Classification != "observed" {
		return errors.New("workload classification must be assumed or observed")
	}
	if workload.Model.ConcurrentRoutesPerActiveDeveloper <= 0 ||
		workload.Model.PeakActiveShare <= 0 || workload.Model.PeakActiveShare > 1 ||
		workload.Model.TrafficRouteShare < 0 || workload.Model.TrafficRouteShare > 1 ||
		workload.Model.IdleRouteShare < 0 || workload.Model.IdleRouteShare > 1 ||
		math.Abs(workload.Model.TrafficRouteShare+workload.Model.IdleRouteShare-1) > 0.000001 {
		return errors.New("workload route and developer shares are invalid")
	}
	if workload.Traffic.PersistentStreamsPerBusyRoute < 0 ||
		workload.Traffic.FreshConnectionsPerBusyRouteMinute < 0 ||
		workload.Traffic.TypicalResponseBytes <= 0 ||
		workload.Traffic.BurstConnectionsPerRoute < 0 || workload.Traffic.BurstResponseBytes <= 0 {
		return errors.New("workload traffic values are invalid")
	}
	if len(workload.Phases) == 0 {
		return errors.New("workload must define phases")
	}
	phaseNames := make(map[string]struct{}, len(workload.Phases))
	for _, phase := range workload.Phases {
		if phase.Name == "" || phase.DurationSeconds <= 0 || phase.TimeoutSeconds < phase.DurationSeconds {
			return fmt.Errorf("workload phase %q has invalid durations", phase.Name)
		}
		if _, found := phaseNames[phase.Name]; found {
			return fmt.Errorf("workload phase %q is duplicated", phase.Name)
		}
		phaseNames[phase.Name] = struct{}{}
	}
	if profile.Machines.Edge.Count != 1 || profile.Machines.Edge.Size == "" ||
		profile.Machines.Worker.Size == "" || profile.Machines.Worker.Capacity <= 0 ||
		profile.Machines.Driver.Size == "" {
		return errors.New("suite Machine configuration is invalid")
	}
	if profile.HostedWorkerLimits.Minimum != 2 || profile.HostedWorkerLimits.Maximum < profile.HostedWorkerLimits.Minimum {
		return errors.New("hosted worker limits must have a two-worker floor")
	}
	for _, size := range []string{profile.Machines.Edge.Size, profile.Machines.Worker.Size, profile.Machines.Driver.Size} {
		if pricing.MachinePerSecond[size] <= 0 {
			return fmt.Errorf("pricing is missing Machine size %q", size)
		}
	}
	if pricing.Currency != "USD" || pricing.PublicEgressPerGB < 0 || pricing.SourceURL == "" {
		return errors.New("pricing profile is invalid")
	}
	return nil
}

func validateSuiteDefinition(name string, definition suiteDefinition, profile suiteProfile) error {
	if len(definition.Workers) == 0 || definition.RoutesPerDriver <= 0 ||
		definition.PhaseDurationScale <= 0 || definition.PhaseDurationScale > 1 {
		return fmt.Errorf("suite %q has invalid matrix settings", name)
	}
	if len(definition.TotalRoutes) != 0 && definition.RoutesPerWorker != 0 {
		return fmt.Errorf("suite %q cannot set total_routes and routes_per_worker together", name)
	}
	if len(definition.TotalRoutes) == 0 && definition.RoutesPerWorker == 0 && !definition.RequiresSchedulingTarget {
		return fmt.Errorf("suite %q does not define routes", name)
	}
	for _, workers := range definition.Workers {
		if workers <= 0 || workers > profile.HostedWorkerLimits.Maximum {
			return fmt.Errorf("suite %q worker count %d is outside benchmark limits", name, workers)
		}
	}
	for _, routes := range definition.TotalRoutes {
		if routes <= 0 {
			return fmt.Errorf("suite %q route count must be positive", name)
		}
	}
	return nil
}

func parseWorkerCounts(value string, maximum int) ([]int, error) {
	parts := strings.Split(value, ",")
	workers := make([]int, 0, len(parts))
	seen := make(map[int]struct{}, len(parts))
	for _, part := range parts {
		count, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || count <= 0 || count > maximum {
			return nil, fmt.Errorf("BENCH_WORKERS must contain counts between 1 and %d", maximum)
		}
		if _, found := seen[count]; found {
			return nil, fmt.Errorf("BENCH_WORKERS contains duplicate count %d", count)
		}
		seen[count] = struct{}{}
		workers = append(workers, count)
	}
	return workers, nil
}

func workloadDurations(workload workloadProfile, scale float64) (int64, int64) {
	var expected, maximum int64
	for _, phase := range workload.Phases {
		expected += max(int64(math.Ceil(float64(phase.DurationSeconds)*scale)), 1)
		maximum += max(int64(math.Ceil(float64(phase.TimeoutSeconds)*scale)), 1)
	}
	return expected, maximum
}

func expandCells(
	suiteName string,
	definition suiteDefinition,
	profile suiteProfile,
	workload workloadProfile,
	expectedSeconds, maximumSeconds int64,
) ([]planCell, error) {
	var cells []planCell
	for _, workers := range definition.Workers {
		routeCounts := definition.TotalRoutes
		if definition.RoutesPerWorker != 0 {
			routeCounts = []int{workers * definition.RoutesPerWorker}
		}
		for _, routes := range routeCounts {
			if routes > workers*profile.Machines.Worker.Capacity {
				return nil, fmt.Errorf("suite %q cell with %d workers cannot hold %d routes", suiteName, workers, routes)
			}
			drivers := max((routes+definition.RoutesPerDriver-1)/definition.RoutesPerDriver, 1)
			for repetition := 1; repetition <= definition.Repetitions; repetition++ {
				cells = append(cells, planCell{
					ID:         fmt.Sprintf("%s-w%d-r%d-rep%d", suiteName, workers, routes, repetition),
					Repetition: repetition, Workers: workers, Routes: routes,
					RoutesPerWorker: float64(routes) / float64(workers), Drivers: drivers,
					ExpectedDurationSeconds: expectedSeconds, MaximumDurationSeconds: maximumSeconds,
					ExpectedNetworkGB: modeledNetworkGB(routes, expectedSeconds, definition.PhaseDurationScale, workload),
				})
			}
		}
	}
	return cells, nil
}

func modeledNetworkGB(routes int, _ int64, scale float64, workload workloadProfile) float64 {
	developmentSeconds := 0.0
	for _, phase := range workload.Phases {
		if phase.Name == "development" {
			developmentSeconds = math.Ceil(float64(phase.DurationSeconds) * scale)
			break
		}
	}
	busyRoutes := float64(routes) * workload.Model.TrafficRouteShare
	typicalResponses := float64(routes) + busyRoutes*float64(workload.Traffic.PersistentStreamsPerBusyRoute) +
		busyRoutes*workload.Traffic.FreshConnectionsPerBusyRouteMinute*developmentSeconds/60
	burstResponses := busyRoutes * float64(workload.Traffic.BurstConnectionsPerRoute)
	bytes := typicalResponses*float64(workload.Traffic.TypicalResponseBytes) +
		burstResponses*float64(workload.Traffic.BurstResponseBytes)
	return bytes / 1_000_000_000
}

func machineRate(pricing pricingProfile, size string, count int) float64 {
	return pricing.MachinePerSecond[size] * float64(count)
}

func configuredOverrides() map[string]string {
	overrides := make(map[string]string)
	for _, name := range []string{
		"BENCH_SUITE", "BENCH_PROFILE", "BENCH_WORKLOAD", "BENCH_PRICING", "BENCH_WORKERS",
		"BENCH_ROUTES_PER_WORKER", "BENCH_REPETITIONS",
	} {
		if value, found := os.LookupEnv(name); found {
			overrides[name] = value
		}
	}
	return overrides
}

func profileWarnings(now time.Time, profile suiteProfile, workload workloadProfile, pricing pricingProfile) []string {
	var warnings []string
	profiles := []struct{ label, date string }{
		{label: "suite profile", date: profile.UpdatedDate},
		{label: "workload profile", date: workload.UpdatedDate},
		{label: "pricing snapshot", date: pricing.SnapshotDate},
	}
	for _, profile := range profiles {
		date, _ := time.Parse(time.DateOnly, profile.date)
		if now.Sub(date) > profileStaleAfter {
			warnings = append(warnings, fmt.Sprintf("%s is more than 90 days old (%s)", profile.label, profile.date))
		}
	}
	return warnings
}

func writeHumanPlan(output io.Writer, plan benchmarkPlan) {
	fmt.Fprintln(output, "Benchmark plan (READ ONLY)")
	fmt.Fprintf(output, "Profile: %s  Suite: %s  Region: %s  Transport: %s\n", plan.ProfileID, plan.Suite, plan.Region, plan.Transport)
	fmt.Fprintf(output, "Machines: %dx %s edge, Nx %s workers, %s drivers\n\n",
		plan.Machines.Edge.Count, plan.Machines.Edge.Size, plan.Machines.Worker.Size, plan.Machines.Driver.Size)

	fmt.Fprintln(output, "WORKLOAD ASSUMPTIONS (NOT OBSERVED)")
	fmt.Fprintf(output, "Workload: %s  Classification: %s  Seed: %d\n", plan.Workload.ID, plan.Workload.Classification, plan.Workload.Seed)
	fmt.Fprintf(output, "Routes/active developer: %d  Peak active share: %.0f%%  Busy routes: %.0f%%  Idle routes: %.0f%%\n",
		plan.Workload.Model.ConcurrentRoutesPerActiveDeveloper, plan.Workload.Model.PeakActiveShare*100,
		plan.Workload.Model.TrafficRouteShare*100, plan.Workload.Model.IdleRouteShare*100)
	fmt.Fprintf(output, "Busy-route streams: %d persistent, %.2f fresh/min  Responses: %d bytes typical, %d bytes burst\n",
		plan.Workload.Traffic.PersistentStreamsPerBusyRoute, plan.Workload.Traffic.FreshConnectionsPerBusyRouteMinute,
		plan.Workload.Traffic.TypicalResponseBytes, plan.Workload.Traffic.BurstResponseBytes)
	fmt.Fprintf(output, "Burst: %d connections/participating route  Restart interval: %s  Active session: %s  Active weekdays/month: %d\n",
		plan.Workload.Traffic.BurstConnectionsPerRoute,
		time.Duration(plan.Workload.Model.AverageRouteRestartIntervalSeconds)*time.Second,
		time.Duration(plan.Workload.Model.TypicalActiveSessionSeconds)*time.Second,
		plan.Workload.Model.ActiveWeekdaysPerMonth)
	fmt.Fprintf(output, "Capacity transport: %.0f%% DERP\n\n", plan.Workload.Transport.DERPShare*100)

	fmt.Fprintln(output, "Cells")
	table := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "ID\tWORKERS\tROUTES\tROUTES/WORKER\tDRIVERS\tEXPECTED\tTIMEOUT")
	for _, cell := range plan.Cells {
		fmt.Fprintf(table, "%s\t%d\t%d\t%.0f\t%d\t%s\t%s\n", cell.ID, cell.Workers, cell.Routes,
			cell.RoutesPerWorker, cell.Drivers, durationString(cell.ExpectedDurationSeconds), durationString(cell.MaximumDurationSeconds))
	}
	_ = table.Flush()
	fmt.Fprintf(output, "\nTotals: %d cells, %d result rows, %s expected, %s maximum\n",
		len(plan.Cells), plan.ExpectedResultRows, durationString(plan.ExpectedDurationSeconds), durationString(plan.MaximumDurationSeconds))
	fmt.Fprintf(output, "Expected spend: $%.4f %s ($%.4f compute, $%.4f public egress)\n",
		plan.ExpectedSpend.TotalUSD, plan.Pricing.Currency, plan.ExpectedSpend.ComputeUSD, plan.ExpectedSpend.PublicEgressUSD)
	fmt.Fprintf(output, "Maximum spend: $%.4f %s ($%.4f compute, $%.4f public egress)\n",
		plan.MaximumSpend.TotalUSD, plan.Pricing.Currency, plan.MaximumSpend.ComputeUSD, plan.MaximumSpend.PublicEgressUSD)
	fmt.Fprintf(output, "Pricing: %s snapshot %s (%s)\n", plan.Pricing.ID, plan.Pricing.SnapshotDate, plan.Pricing.SourceURL)

	fmt.Fprintln(output, "\nRequired inputs")
	for _, requirement := range plan.RequiredInputs {
		fmt.Fprintf(output, "- %s\n", requirement)
	}
	if len(plan.Dependencies) != 0 {
		fmt.Fprintln(output, "\nDependencies")
		for _, dependency := range plan.Dependencies {
			fmt.Fprintf(output, "- %s\n", dependency)
		}
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
	if len(plan.Warnings) != 0 {
		fmt.Fprintln(output, "\nWarnings")
		for _, warning := range plan.Warnings {
			fmt.Fprintf(output, "- %s\n", warning)
		}
	}
	for _, note := range plan.Workload.ReferenceNotes {
		fmt.Fprintf(output, "- %s\n", note)
	}
}

func durationString(seconds int64) string {
	return (time.Duration(seconds) * time.Second).String()
}
