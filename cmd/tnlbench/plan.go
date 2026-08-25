package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

const profileStaleAfter = 90 * 24 * time.Hour

const (
	benchmarkCertificateAuthorityPebble      = "pebble"
	benchmarkCertificateAuthorityLetsEncrypt = "letsencrypt"
)

type planCommand struct {
	Suite        string `name:"suite" env:"BENCH_SUITE" default:"smoke" help:"Named suite to expand: smoke, scout, confirm, or compatibility."`
	Axis         string `name:"axis" env:"BENCH_AXIS" help:"Select one axis from the suite, preserving its targets and order."`
	ProfileFile  string `name:"profile" env:"BENCH_PROFILE" default:"benchmarks/suites/fly-production.json" type:"path" help:"Production-candidate benchmark profile."`
	Routes       int    `name:"routes" env:"BENCH_ROUTES" help:"Route count overriding the suite; required for confirm."`
	FreshRate    int    `name:"fresh-connections-per-second" env:"BENCH_FRESH_CONNECTIONS_PER_SECOND" help:"Total fresh visitor connections per second overriding the suite; required for confirm."`
	HeldStreams  int    `name:"held-streams" env:"BENCH_HELD_STREAMS" help:"Held-open visitor streams overriding the suite; required for confirm."`
	ChurnRate    int    `name:"lifecycle-churn-per-second" env:"BENCH_LIFECYCLE_CHURN_PER_SECOND" help:"Route-session lifecycle operations per second overriding confirm."`
	PayloadBytes int    `name:"payload-bytes" env:"BENCH_PAYLOAD_BYTES" help:"Fresh-response bytes overriding confirm; defaults to 16384."`
	Repetitions  int    `name:"repetitions" env:"BENCH_REPETITIONS" help:"Repetitions overriding the suite."`
	Format       string `name:"format" env:"BENCH_PLAN_FORMAT" enum:"human,json" default:"human" help:"Plan output format."`
}

type benchmarkProfile struct {
	SchemaVersion   int                        `json:"schema_version"`
	ID              string                     `json:"id"`
	UpdatedDate     string                     `json:"updated_date"`
	Region          string                     `json:"region"`
	Topology        benchmarkTopology          `json:"topology"`
	Machines        benchmarkMachines          `json:"machines"`
	ManagedPostgres benchmarkManagedPostgres   `json:"managed_postgres"`
	WorkerLimits    benchmarkWorkerLimits      `json:"worker_limits"`
	Pricing         benchmarkPricing           `json:"pricing"`
	Suites          map[string]suiteDefinition `json:"suites"`
}

type benchmarkTopology struct {
	ControlProcesses         int `json:"control_processes"`
	IngressProcesses         int `json:"ingress_processes"`
	RelayServices            int `json:"relay_services"`
	RelayProcessesPerService int `json:"relay_processes_per_service"`
}

type benchmarkMachines struct {
	Control     string `json:"control"`
	Ingress     string `json:"ingress"`
	Relay       string `json:"relay"`
	Pebble      string `json:"pebble"`
	Coordinator string `json:"coordinator"`
	Publisher   string `json:"publisher"`
	Load        string `json:"load"`
}

type benchmarkManagedPostgres struct {
	Plan                     string `json:"plan"`
	PostgresMajorVersion     int    `json:"postgres_major_version"`
	StorageGB                int    `json:"storage_gb"`
	ProvisionExpectedSeconds int    `json:"provision_expected_seconds"`
	ProvisionTimeoutSeconds  int    `json:"provision_timeout_seconds"`
}

type benchmarkWorkerLimits struct {
	PublisherMachines             int `json:"publisher_machines"`
	RoutesPerPublisher            int `json:"routes_per_publisher"`
	RoutesPerChurnRoute           int `json:"routes_per_churn_route"`
	PublisherVolumeGB             int `json:"publisher_volume_gb"`
	FreshConnectionsPerLoadSecond int `json:"fresh_connections_per_load_second"`
	HeldStreamsPerLoad            int `json:"held_streams_per_load"`
}

type benchmarkPricing struct {
	SnapshotDate                        string             `json:"snapshot_date"`
	SourceURL                           string             `json:"source_url"`
	ManagedPostgresSourceURL            string             `json:"managed_postgres_source_url"`
	Route53SourceURL                    string             `json:"route53_source_url"`
	MachinePerSecondUSD                 map[string]float64 `json:"machine_per_second_usd"`
	PublicIPv4PerHour                   float64            `json:"public_ipv4_per_hour_usd"`
	VolumeGBPerMonthUSD                 float64            `json:"volume_gb_per_month_usd"`
	ManagedPostgresPlanPerMonthUSD      map[string]float64 `json:"managed_postgres_plan_per_month_usd"`
	ManagedPostgresStorageGBPerMonthUSD float64            `json:"managed_postgres_storage_gb_per_month_usd"`
	HostedZonePerMonth                  float64            `json:"hosted_zone_per_month_usd"`
}

type suiteDefinition struct {
	Repetitions          int                 `json:"repetitions"`
	RequiresTarget       bool                `json:"requires_target,omitempty"`
	CertificateAuthority string              `json:"certificate_authority"`
	Cells                []benchmarkCellSpec `json:"cells"`
}

type benchmarkCellSpec struct {
	Axis                      string `json:"axis"`
	Routes                    int    `json:"routes"`
	FreshConnectionsPerSecond int    `json:"fresh_connections_per_second"`
	HeldStreams               int    `json:"held_streams"`
	LifecycleChurnPerSecond   int    `json:"lifecycle_churn_per_second"`
	PayloadBytes              int    `json:"payload_bytes"`
	WarmupSeconds             int    `json:"warmup_seconds"`
	DurationSeconds           int    `json:"duration_seconds"`
}

type benchmarkPlan struct {
	SchemaVersion                   int                      `json:"schema_version"`
	ReadOnly                        bool                     `json:"read_only"`
	ProfileID                       string                   `json:"profile_id"`
	Suite                           string                   `json:"suite"`
	Axis                            string                   `json:"axis,omitempty"`
	Region                          string                   `json:"region"`
	Topology                        benchmarkTopology        `json:"topology"`
	Machines                        benchmarkMachines        `json:"machines"`
	ManagedPostgres                 benchmarkManagedPostgres `json:"managed_postgres"`
	WorkerLimits                    benchmarkWorkerLimits    `json:"worker_limits"`
	CertificateAuthority            string                   `json:"certificate_authority"`
	Cells                           []planCell               `json:"cells"`
	ExpectedDurationSeconds         int64                    `json:"expected_duration_seconds"`
	MaximumDurationSeconds          int64                    `json:"maximum_duration_seconds"`
	ExpectedResultRows              int                      `json:"expected_result_rows"`
	ExpectedSpendUSD                float64                  `json:"expected_spend_usd"`
	MaximumSpendUSD                 float64                  `json:"maximum_spend_usd"`
	PricingSnapshotDate             string                   `json:"pricing_snapshot_date"`
	PricingSourceURL                string                   `json:"pricing_source_url"`
	ManagedPostgresPricingSourceURL string                   `json:"managed_postgres_pricing_source_url"`
	Route53PricingSourceURL         string                   `json:"route53_pricing_source_url"`
	RequiredInputs                  []string                 `json:"required_inputs"`
	Overrides                       map[string]string        `json:"overrides"`
	Warnings                        []string                 `json:"warnings"`
}

type planCell struct {
	ID                        string  `json:"id"`
	Axis                      string  `json:"axis"`
	Sequence                  int     `json:"sequence"`
	Repetition                int     `json:"repetition"`
	Routes                    int     `json:"routes"`
	FreshConnectionsPerSecond int     `json:"fresh_connections_per_second"`
	HeldStreams               int     `json:"held_streams"`
	LifecycleChurnPerSecond   int     `json:"lifecycle_churn_per_second"`
	PayloadBytes              int     `json:"payload_bytes"`
	PublisherWorkers          int     `json:"publisher_workers"`
	LoadWorkers               int     `json:"load_workers"`
	FreshConnectionsPerWorker float64 `json:"fresh_connections_per_worker_second"`
	HeldStreamsPerWorker      int     `json:"held_streams_per_worker"`
	WarmupSeconds             int     `json:"warmup_seconds"`
	DurationSeconds           int     `json:"duration_seconds"`
	TimeoutSeconds            int     `json:"timeout_seconds"`
	EstimatedMonthlyCostUSD   float64 `json:"estimated_monthly_cost_usd"`
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
	overridingTarget := c.Routes != 0 || c.FreshRate != 0 || c.HeldStreams != 0 || c.ChurnRate != 0 || c.PayloadBytes != 0
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
		payloadBytes := c.PayloadBytes
		if payloadBytes == 0 {
			payloadBytes = 16 << 10
		}
		definition.Cells = []benchmarkCellSpec{{
			Axis:   "confirm",
			Routes: c.Routes, FreshConnectionsPerSecond: c.FreshRate, HeldStreams: c.HeldStreams,
			LifecycleChurnPerSecond: c.ChurnRate, PayloadBytes: payloadBytes,
			WarmupSeconds: warmup, DurationSeconds: duration,
		}}
	}
	if c.Repetitions != 0 {
		definition.Repetitions = c.Repetitions
	}
	if definition.Repetitions < 1 || definition.Repetitions > 10 {
		return benchmarkPlan{}, errors.New("repetitions must be between 1 and 10")
	}
	if c.Axis != "" {
		found := false
		for _, spec := range definition.Cells {
			found = found || spec.Axis == c.Axis
		}
		if !found {
			return benchmarkPlan{}, fmt.Errorf("axis %q is not present in suite %q", c.Axis, c.Suite)
		}
	}

	plan := benchmarkPlan{
		SchemaVersion: 3, ReadOnly: true, ProfileID: profile.ID, Suite: c.Suite, Region: profile.Region,
		Axis:     c.Axis,
		Topology: profile.Topology, Machines: profile.Machines, ManagedPostgres: profile.ManagedPostgres,
		WorkerLimits:            profile.WorkerLimits,
		CertificateAuthority:    definition.CertificateAuthority,
		ExpectedDurationSeconds: int64(profile.ManagedPostgres.ProvisionExpectedSeconds),
		MaximumDurationSeconds:  int64(profile.ManagedPostgres.ProvisionTimeoutSeconds),
		PricingSnapshotDate:     profile.Pricing.SnapshotDate, PricingSourceURL: profile.Pricing.SourceURL,
		ManagedPostgresPricingSourceURL: profile.Pricing.ManagedPostgresSourceURL,
		Route53PricingSourceURL:         profile.Pricing.Route53SourceURL,
		RequiredInputs: []string{
			"Fly organization access through flyctl", "AWS credentials with Route 53 access",
			"Fly Managed Postgres access in the selected region", "an existing public Route 53 parent zone", "an ACME account email",
		},
		Overrides: configuredOverrides(),
		Warnings: []string{
			"Planning is read-only; execution creates paid Fly Machines, Managed Postgres, public IPv4, and Route 53 resources.",
			"Spend excludes image builds, public egress, DNS queries, ACME, failed retries, and retained resources except the maximum's explicit allowances.",
			"Maximum spend models one retained Managed Postgres month, the configured publisher volumes for one month, and two hosted-zone charges; longer retention can cost more.",
		},
	}
	if definition.CertificateAuthority == benchmarkCertificateAuthorityLetsEncrypt {
		plan.Warnings = append(plan.Warnings, "The compatibility suite uses Let's Encrypt; keep it small and avoid repeated runs that consume public CA rate limits.")
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
		if c.Axis != "" && spec.Axis != c.Axis {
			continue
		}
		if err := validateCellSpec(spec); err != nil {
			return benchmarkPlan{}, fmt.Errorf("suite %q: %w", c.Suite, err)
		}
		for repetition := 1; repetition <= definition.Repetitions; repetition++ {
			if spec.Routes > profile.WorkerLimits.PublisherMachines*profile.WorkerLimits.RoutesPerPublisher {
				return benchmarkPlan{}, fmt.Errorf("suite %q: route target exceeds publisher generator capacity", c.Suite)
			}
			publishers := divideRoundUp(spec.Routes, profile.WorkerLimits.RoutesPerPublisher)
			loadWorkers := max(
				divideRoundUp(spec.FreshConnectionsPerSecond, profile.WorkerLimits.FreshConnectionsPerLoadSecond),
				divideRoundUp(spec.HeldStreams, profile.WorkerLimits.HeldStreamsPerLoad),
				1,
			)
			cell := planCell{
				ID: fmt.Sprintf("%s-%s-r%d-c%d-s%d-l%d-b%d-rep%d", c.Suite, spec.Axis, spec.Routes,
					spec.FreshConnectionsPerSecond, spec.HeldStreams, spec.LifecycleChurnPerSecond, spec.PayloadBytes, repetition),
				Axis: spec.Axis, Sequence: sequence, Repetition: repetition, Routes: spec.Routes,
				FreshConnectionsPerSecond: spec.FreshConnectionsPerSecond, HeldStreams: spec.HeldStreams,
				LifecycleChurnPerSecond: spec.LifecycleChurnPerSecond, PayloadBytes: spec.PayloadBytes,
				PublisherWorkers: publishers, LoadWorkers: loadWorkers,
				FreshConnectionsPerWorker: float64(spec.FreshConnectionsPerSecond) / float64(loadWorkers),
				HeldStreamsPerWorker:      divideRoundUp(spec.HeldStreams, loadWorkers),
				WarmupSeconds:             spec.WarmupSeconds, DurationSeconds: spec.DurationSeconds,
				TimeoutSeconds: spec.WarmupSeconds + spec.DurationSeconds + 15*60,
			}
			cell.EstimatedMonthlyCostUSD = estimatedMonthlyCost(profile, cell, definition.CertificateAuthority)
			plan.Cells = append(plan.Cells, cell)
			plan.ExpectedDurationSeconds += int64(spec.WarmupSeconds + spec.DurationSeconds + 4*60)
			plan.MaximumDurationSeconds += int64(cell.TimeoutSeconds)
			plan.ExpectedResultRows += publishers + loadWorkers
			plan.ExpectedSpendUSD += estimatedCellSpend(profile, cell, spec.WarmupSeconds+spec.DurationSeconds+4*60, definition.CertificateAuthority)
			plan.MaximumSpendUSD += estimatedCellSpend(profile, cell, cell.TimeoutSeconds, definition.CertificateAuthority)
		}
	}
	// One Managed Postgres cluster, public app IPv4s, and two transient hosted zones.
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
	if profile.SchemaVersion != 3 || profile.ID == "" || len(profile.Region) != 3 || !validFlySlug(profile.Region) {
		return errors.New("benchmark profile has an invalid schema or identity")
	}
	for label, value := range map[string]string{"updated_date": profile.UpdatedDate, "pricing snapshot_date": profile.Pricing.SnapshotDate} {
		if _, err := time.Parse(time.DateOnly, value); err != nil {
			return fmt.Errorf("%s must use YYYY-MM-DD", label)
		}
	}
	if profile.Topology.ControlProcesses <= 0 || profile.Topology.ControlProcesses > 10 ||
		profile.Topology.IngressProcesses <= 0 || profile.Topology.IngressProcesses > 10 ||
		profile.Topology.RelayServices < 2 || profile.Topology.RelayServices > 26 ||
		profile.Topology.RelayProcessesPerService <= 0 || profile.Topology.RelayProcessesPerService > 10 {
		return errors.New("benchmark topology is invalid")
	}
	if profile.WorkerLimits.PublisherMachines <= 0 || profile.WorkerLimits.PublisherMachines > 16 ||
		profile.WorkerLimits.RoutesPerPublisher <= 0 || profile.WorkerLimits.RoutesPerChurnRoute <= 0 ||
		profile.WorkerLimits.RoutesPerChurnRoute > profile.WorkerLimits.RoutesPerPublisher ||
		profile.WorkerLimits.RoutesPerPublisher%profile.WorkerLimits.RoutesPerChurnRoute != 0 ||
		profile.WorkerLimits.PublisherVolumeGB <= 0 || profile.WorkerLimits.PublisherVolumeGB > 10 ||
		profile.WorkerLimits.FreshConnectionsPerLoadSecond <= 0 ||
		profile.WorkerLimits.FreshConnectionsPerLoadSecond >= 40 || profile.WorkerLimits.HeldStreamsPerLoad <= 0 {
		return errors.New("benchmark worker limits are invalid or could exercise the ingress source limiter")
	}
	database := profile.ManagedPostgres
	if database.Plan == "" || database.Plan != strings.ToLower(database.Plan) ||
		profile.Pricing.ManagedPostgresPlanPerMonthUSD[database.Plan] <= 0 ||
		(database.PostgresMajorVersion != 16 && database.PostgresMajorVersion != 17) ||
		database.StorageGB < 10 || database.StorageGB > 500 ||
		database.ProvisionExpectedSeconds <= 0 ||
		database.ProvisionTimeoutSeconds < database.ProvisionExpectedSeconds {
		return errors.New("benchmark Managed Postgres configuration is invalid")
	}
	sizes := []string{
		profile.Machines.Control, profile.Machines.Ingress, profile.Machines.Relay,
		profile.Machines.Pebble, profile.Machines.Coordinator, profile.Machines.Publisher, profile.Machines.Load,
	}
	for _, size := range sizes {
		if size == "" || profile.Pricing.MachinePerSecondUSD[size] <= 0 {
			return fmt.Errorf("pricing is missing machine size %q", size)
		}
	}
	if profile.Pricing.SourceURL == "" || profile.Pricing.ManagedPostgresSourceURL == "" || profile.Pricing.Route53SourceURL == "" ||
		profile.Pricing.PublicIPv4PerHour < 0 || profile.Pricing.VolumeGBPerMonthUSD <= 0 ||
		profile.Pricing.ManagedPostgresStorageGBPerMonthUSD < 0 ||
		profile.Pricing.HostedZonePerMonth < 0 {
		return errors.New("benchmark pricing is invalid")
	}
	for name, definition := range profile.Suites {
		if definition.Repetitions < 1 || definition.Repetitions > 10 || len(definition.Cells) == 0 && !definition.RequiresTarget ||
			definition.CertificateAuthority != benchmarkCertificateAuthorityPebble &&
				definition.CertificateAuthority != benchmarkCertificateAuthorityLetsEncrypt {
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
	if !validBenchmarkAxis(cell.Axis) || cell.Routes <= 0 || cell.Routes > 10_000 || cell.FreshConnectionsPerSecond <= 0 ||
		cell.FreshConnectionsPerSecond > 10_000 || cell.HeldStreams < 0 || cell.HeldStreams > 100_000 ||
		cell.LifecycleChurnPerSecond < 0 || cell.LifecycleChurnPerSecond > 1_000 ||
		cell.PayloadBytes <= 0 || cell.PayloadBytes > 16<<20 || cell.WarmupSeconds < 0 || cell.DurationSeconds <= 0 {
		return fmt.Errorf("invalid cell r%d-c%d-s%d", cell.Routes, cell.FreshConnectionsPerSecond, cell.HeldStreams)
	}
	return nil
}

func validBenchmarkAxis(axis string) bool {
	switch axis {
	case "smoke", "active_routes", "lifecycle_churn", "fresh_connections", "held_streams", "bandwidth", "confirm", "compatibility":
		return true
	default:
		return false
	}
}

func divideRoundUp(value, divisor int) int {
	if value == 0 {
		return 0
	}
	return (value + divisor - 1) / divisor
}

func estimatedCellSpend(profile benchmarkProfile, cell planCell, seconds int, certificateAuthority string) float64 {
	fixedRate := float64(profile.Topology.ControlProcesses)*profile.Pricing.MachinePerSecondUSD[profile.Machines.Control] +
		float64(profile.Topology.IngressProcesses)*profile.Pricing.MachinePerSecondUSD[profile.Machines.Ingress] +
		float64(profile.Topology.RelayServices*profile.Topology.RelayProcessesPerService)*profile.Pricing.MachinePerSecondUSD[profile.Machines.Relay] +
		profile.Pricing.MachinePerSecondUSD[profile.Machines.Coordinator]
	if certificateAuthority == benchmarkCertificateAuthorityPebble {
		fixedRate += profile.Pricing.MachinePerSecondUSD[profile.Machines.Pebble]
	}
	workerRate := float64(cell.PublisherWorkers)*profile.Pricing.MachinePerSecondUSD[profile.Machines.Publisher] +
		float64(cell.LoadWorkers)*profile.Pricing.MachinePerSecondUSD[profile.Machines.Load]
	return (fixedRate + workerRate) * float64(seconds)
}

func fixedResourceSpend(profile benchmarkProfile, seconds int64, includeRetainedResources bool) float64 {
	hours := float64(seconds) / 3600
	monthShare := float64(seconds) / (30 * 24 * 3600)
	databaseMonthly := profile.Pricing.ManagedPostgresPlanPerMonthUSD[profile.ManagedPostgres.Plan] +
		float64(profile.ManagedPostgres.StorageGB)*profile.Pricing.ManagedPostgresStorageGBPerMonthUSD
	volumeMonthly := float64(profile.WorkerLimits.PublisherMachines*profile.WorkerLimits.PublisherVolumeGB) * profile.Pricing.VolumeGBPerMonthUSD
	publicIPv4s := float64(profile.Topology.RelayServices + 2) // control, ingress, and relay apps; coordinator uses shared IPv4
	spend := publicIPv4s*profile.Pricing.PublicIPv4PerHour*hours + (databaseMonthly+volumeMonthly)*monthShare
	if includeRetainedResources {
		spend += databaseMonthly + volumeMonthly + 2*profile.Pricing.HostedZonePerMonth
	}
	return spend
}

func estimatedMonthlyCost(profile benchmarkProfile, cell planCell, certificateAuthority string) float64 {
	const monthSeconds = 30 * 24 * 3600
	machineRate := float64(profile.Topology.ControlProcesses)*profile.Pricing.MachinePerSecondUSD[profile.Machines.Control] +
		float64(profile.Topology.IngressProcesses)*profile.Pricing.MachinePerSecondUSD[profile.Machines.Ingress] +
		float64(profile.Topology.RelayServices*profile.Topology.RelayProcessesPerService)*profile.Pricing.MachinePerSecondUSD[profile.Machines.Relay] +
		profile.Pricing.MachinePerSecondUSD[profile.Machines.Coordinator] +
		float64(cell.PublisherWorkers)*profile.Pricing.MachinePerSecondUSD[profile.Machines.Publisher] +
		float64(cell.LoadWorkers)*profile.Pricing.MachinePerSecondUSD[profile.Machines.Load]
	if certificateAuthority == benchmarkCertificateAuthorityPebble {
		machineRate += profile.Pricing.MachinePerSecondUSD[profile.Machines.Pebble]
	}
	volumes := float64(profile.WorkerLimits.PublisherMachines*profile.WorkerLimits.PublisherVolumeGB) * profile.Pricing.VolumeGBPerMonthUSD
	database := profile.Pricing.ManagedPostgresPlanPerMonthUSD[profile.ManagedPostgres.Plan] +
		float64(profile.ManagedPostgres.StorageGB)*profile.Pricing.ManagedPostgresStorageGBPerMonthUSD
	publicAddresses := float64(profile.Topology.RelayServices+2) * profile.Pricing.PublicIPv4PerHour * 30 * 24
	return machineRate*monthSeconds + volumes + database + publicAddresses + 2*profile.Pricing.HostedZonePerMonth
}

func configuredOverrides() map[string]string {
	result := make(map[string]string)
	for _, name := range []string{
		"BENCH_SUITE", "BENCH_AXIS", "BENCH_PROFILE", "BENCH_ROUTES", "BENCH_FRESH_CONNECTIONS_PER_SECOND",
		"BENCH_HELD_STREAMS", "BENCH_LIFECYCLE_CHURN_PER_SECOND", "BENCH_PAYLOAD_BYTES", "BENCH_REPETITIONS",
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
	if plan.Axis != "" {
		fmt.Fprintf(output, "Selected axis: %s\n", plan.Axis)
	}
	fmt.Fprintf(output, "Topology: %d control, %d ingress, %dx%d relay processes\n\n",
		plan.Topology.ControlProcesses, plan.Topology.IngressProcesses,
		plan.Topology.RelayServices, plan.Topology.RelayProcessesPerService)
	fmt.Fprintf(output, "Database: Fly Managed Postgres %s, PostgreSQL %d, %d GB\n\n",
		plan.ManagedPostgres.Plan, plan.ManagedPostgres.PostgresMajorVersion, plan.ManagedPostgres.StorageGB)
	fmt.Fprintf(output, "Publishers: up to %d generators, %d routes/generator, one churn route per %d routes, %d GB persistent state each\n\n",
		plan.WorkerLimits.PublisherMachines, plan.WorkerLimits.RoutesPerPublisher,
		plan.WorkerLimits.RoutesPerChurnRoute, plan.WorkerLimits.PublisherVolumeGB)
	certificateAuthority := "private Pebble"
	if plan.CertificateAuthority == benchmarkCertificateAuthorityLetsEncrypt {
		certificateAuthority = "Let's Encrypt"
	}
	fmt.Fprintf(output, "Certificates: %s\n\n", certificateAuthority)
	table := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "CELL\tAXIS\tROUTES\tCHURN/S\tFRESH/S\tHELD\tPAYLOAD\tPUBLISHERS\tLOAD\tMONTHLY\tDURATION\tTIMEOUT")
	for _, cell := range plan.Cells {
		fmt.Fprintf(table, "%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t$%.2f\t%s\t%s\n",
			cell.ID, cell.Axis, cell.Routes, cell.LifecycleChurnPerSecond,
			cell.FreshConnectionsPerSecond, cell.HeldStreams, cell.PayloadBytes,
			cell.PublisherWorkers, cell.LoadWorkers, cell.EstimatedMonthlyCostUSD,
			time.Duration(cell.DurationSeconds)*time.Second, time.Duration(cell.TimeoutSeconds)*time.Second)
	}
	if err := table.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(output, "\nTotals: %d cells, %d worker result rows, %s expected, %s maximum\n",
		len(plan.Cells), plan.ExpectedResultRows, time.Duration(plan.ExpectedDurationSeconds)*time.Second,
		time.Duration(plan.MaximumDurationSeconds)*time.Second)
	fmt.Fprintf(output, "Estimated spend: $%.4f expected, $%.4f maximum (USD)\n", plan.ExpectedSpendUSD, plan.MaximumSpendUSD)
	fmt.Fprintf(output, "Pricing: snapshot %s (%s; %s; %s)\n", plan.PricingSnapshotDate, plan.PricingSourceURL,
		plan.ManagedPostgresPricingSourceURL, plan.Route53PricingSourceURL)
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
