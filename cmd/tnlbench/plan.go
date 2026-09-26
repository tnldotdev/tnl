package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

const (
	benchmarkCertificateAuthorityPebble      = "pebble"
	benchmarkCertificateAuthorityLetsEncrypt = "letsencrypt"
)

// Both plan and run resolve this exact configuration. The profile contains only
// infrastructure; a run contains one target with repeated measurement windows.
type workloadOptions struct {
	Suite                string        `name:"suite" env:"BENCH_SUITE" default:"smoke" enum:"smoke,target" help:"Small smoke or an explicit target."`
	ProfileFile          string        `name:"profile" env:"BENCH_PROFILE" default:"benchmarks/fly.json" type:"path" help:"Fly infrastructure configuration."`
	PublicURLs           int           `name:"public-urls" env:"BENCH_PUBLIC_URLS" default:"4" help:"Published public URLs."`
	FreshRate            int           `name:"fresh-connections-per-second" env:"BENCH_FRESH_CONNECTIONS_PER_SECOND" default:"16" help:"Total fresh HTTPS requests per second."`
	HeldStreams          int           `name:"held-streams" env:"BENCH_HELD_STREAMS" default:"4" help:"Held visitor streams."`
	Concurrency          int           `name:"concurrency" env:"BENCH_CONCURRENCY" default:"128" help:"Total concurrent fresh requests."`
	QueueSlots           int           `name:"queue-slots" env:"BENCH_QUEUE_SLOTS" default:"8" help:"Total waiting requests, separate from concurrency."`
	PayloadBytes         int           `name:"payload-bytes" env:"BENCH_PAYLOAD_BYTES" default:"32768" help:"Verified response bytes."`
	Repetitions          int           `name:"repetitions" env:"BENCH_REPETITIONS" default:"1" help:"Measurement windows in one deployment."`
	Warmup               time.Duration `name:"warmup" env:"BENCH_WARMUP" default:"5s" help:"Warmup before measurement."`
	Duration             time.Duration `name:"duration" env:"BENCH_DURATION" default:"10s" help:"Fixed offer duration per window."`
	CertificateAuthority string        `name:"certificate-authority" env:"BENCH_CERTIFICATE_AUTHORITY" default:"pebble" enum:"pebble,letsencrypt" help:"PublicURL certificate issuer."`
}

type planCommand struct {
	workloadOptions
	Format string `name:"format" enum:"human,json" default:"human" help:"Plan output format."`
}

type benchmarkProfile struct {
	SchemaVersion   int                      `json:"schema_version"`
	ID              string                   `json:"id"`
	Region          string                   `json:"region"`
	Topology        benchmarkTopology        `json:"topology"`
	Machines        benchmarkMachines        `json:"machines"`
	ManagedPostgres benchmarkManagedPostgres `json:"managed_postgres"`
	WorkerLimits    benchmarkWorkerLimits    `json:"worker_limits"`
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
	PublicURLsPerPublisher        int `json:"public_urls_per_publisher"`
	FreshConnectionsPerLoadSecond int `json:"fresh_connections_per_load_second"`
	HeldStreamsPerLoad            int `json:"held_streams_per_load"`
}
type benchmarkPlan struct {
	SchemaVersion          int                      `json:"schema_version"`
	ReadOnly               bool                     `json:"read_only"`
	ProfileID              string                   `json:"profile_id"`
	Suite                  string                   `json:"suite"`
	Region                 string                   `json:"region"`
	Topology               benchmarkTopology        `json:"topology"`
	Machines               benchmarkMachines        `json:"machines"`
	ManagedPostgres        benchmarkManagedPostgres `json:"managed_postgres"`
	WorkerLimits           benchmarkWorkerLimits    `json:"worker_limits"`
	CertificateAuthority   string                   `json:"certificate_authority"`
	Target                 planCell                 `json:"target"`
	MaximumDurationSeconds int64                    `json:"maximum_duration_seconds"`
}

type planCell struct {
	ID                        string `json:"id"`
	PublicURLs                int    `json:"public_urls"`
	FreshConnectionsPerSecond int    `json:"fresh_connections_per_second"`
	HeldStreams               int    `json:"held_streams"`
	PayloadBytes              int    `json:"payload_bytes"`
	Concurrency               int    `json:"concurrency"`
	QueueSlots                int    `json:"queue_slots"`
	PublisherWorkers          int    `json:"publisher_workers"`
	LoadWorkers               int    `json:"load_workers"`
	WarmupSeconds             int    `json:"warmup_seconds"`
	DurationSeconds           int    `json:"duration_seconds"`
	Repetitions               int    `json:"repetitions"`
	TimeoutSeconds            int    `json:"timeout_seconds"`
}

func (c planCommand) run(stdout io.Writer) error {
	plan, err := c.workloadOptions.build()
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

func (c workloadOptions) build() (benchmarkPlan, error) {
	var profile benchmarkProfile
	if err := decodeJSONFile(c.ProfileFile, &profile); err != nil {
		return benchmarkPlan{}, err
	}
	if err := validateBenchmarkProfile(profile); err != nil {
		return benchmarkPlan{}, err
	}
	if c.Suite != "smoke" && c.Suite != "target" {
		return benchmarkPlan{}, errors.New("suite must be smoke or target")
	}
	if c.PublicURLs < 1 || c.PublicURLs > 10_000 || c.FreshRate < 1 || c.FreshRate > 10_000 || c.HeldStreams < 0 || c.HeldStreams > 100_000 || c.PayloadBytes < 1 || c.PayloadBytes > 16<<20 || c.Concurrency < 1 || c.Concurrency > 100_000 || c.QueueSlots < 0 || c.QueueSlots > 10_000 || c.Repetitions < 1 || c.Repetitions > 10 || c.Warmup < 0 || c.Warmup > 5*time.Minute || c.Duration < time.Second || c.Duration > 10*time.Minute || c.Duration%time.Second != 0 || c.Warmup%time.Second != 0 {
		return benchmarkPlan{}, errors.New("invalid workload shape or duration")
	}
	if c.Suite == "smoke" && (c.PublicURLs > 4 || c.FreshRate > 16 || c.HeldStreams > 4 || c.Repetitions != 1 || c.Duration > 30*time.Second) {
		return benchmarkPlan{}, errors.New("larger workloads require suite target")
	}
	if c.CertificateAuthority != benchmarkCertificateAuthorityPebble && c.CertificateAuthority != benchmarkCertificateAuthorityLetsEncrypt {
		return benchmarkPlan{}, errors.New("invalid certificate authority")
	}
	if c.CertificateAuthority == benchmarkCertificateAuthorityLetsEncrypt && c.Suite != "smoke" {
		return benchmarkPlan{}, errors.New("public CA checks use the small smoke workload")
	}
	publishers := divideRoundUp(c.PublicURLs, profile.WorkerLimits.PublicURLsPerPublisher)
	visitors := max(1, divideRoundUp(c.FreshRate, profile.WorkerLimits.FreshConnectionsPerLoadSecond), divideRoundUp(c.HeldStreams, profile.WorkerLimits.HeldStreamsPerLoad))
	if publishers > profile.WorkerLimits.PublisherMachines || visitors > c.Concurrency {
		return benchmarkPlan{}, errors.New("target exceeds publisher capacity or needs at least one concurrent request per visitor process")
	}
	if 2*publishers+visitors*(c.Repetitions+3)+c.Repetitions+8 > 4096 {
		return benchmarkPlan{}, errors.New("target exceeds bounded coordinator event capacity")
	}
	cell := planCell{ID: fmt.Sprintf("r%d-c%d-s%d-b%d", c.PublicURLs, c.FreshRate, c.HeldStreams, c.PayloadBytes), PublicURLs: c.PublicURLs,
		FreshConnectionsPerSecond: c.FreshRate, HeldStreams: c.HeldStreams, PayloadBytes: c.PayloadBytes,
		Concurrency: c.Concurrency, QueueSlots: c.QueueSlots, PublisherWorkers: publishers, LoadWorkers: visitors,
		WarmupSeconds: int(c.Warmup / time.Second), DurationSeconds: int(c.Duration / time.Second), Repetitions: c.Repetitions,
		TimeoutSeconds: divideRoundUp(divideRoundUp(c.PublicURLs, publishers), 4)*30 + 5*60 + divideRoundUp(c.HeldStreams, visitors)*5 + divideRoundUp(c.PublicURLs, visitors)*5 + int(c.Warmup/time.Second) + c.Repetitions*(int(c.Duration/time.Second)+30) + 2*60,
	}
	return benchmarkPlan{SchemaVersion: 4, ReadOnly: true, ProfileID: profile.ID, Suite: c.Suite, Region: profile.Region,
		Topology: profile.Topology, Machines: profile.Machines, ManagedPostgres: profile.ManagedPostgres, WorkerLimits: profile.WorkerLimits,
		CertificateAuthority: c.CertificateAuthority, Target: cell,
		MaximumDurationSeconds: int64(profile.ManagedPostgres.ProvisionTimeoutSeconds + cell.TimeoutSeconds + 20*60),
	}, nil
}

func validateBenchmarkProfile(p benchmarkProfile) error {
	if p.SchemaVersion != 4 || p.ID == "" || len(p.Region) != 3 || !validFlySlug(p.Region) {
		return errors.New("invalid infrastructure profile identity")
	}
	if p.Topology.ControlProcesses < 1 || p.Topology.ControlProcesses > 10 || p.Topology.IngressProcesses < 1 || p.Topology.IngressProcesses > 10 || p.Topology.RelayServices < 2 || p.Topology.RelayServices > 26 || p.Topology.RelayProcessesPerService < 1 || p.Topology.RelayProcessesPerService > 10 {
		return errors.New("invalid topology")
	}
	if p.WorkerLimits.PublisherMachines < 1 || p.WorkerLimits.PublisherMachines > 16 || p.WorkerLimits.PublicURLsPerPublisher < 1 || p.WorkerLimits.PublicURLsPerPublisher > 10_000 || p.WorkerLimits.FreshConnectionsPerLoadSecond < 1 || p.WorkerLimits.FreshConnectionsPerLoadSecond >= 40 || p.WorkerLimits.HeldStreamsPerLoad < 1 {
		return errors.New("invalid generator limits or unsafe per-source rate")
	}
	db := p.ManagedPostgres
	if !validFlySlug(db.Plan) || (db.PostgresMajorVersion != 16 && db.PostgresMajorVersion != 17) || db.StorageGB < 10 || db.StorageGB > 500 || db.ProvisionExpectedSeconds <= 0 || db.ProvisionTimeoutSeconds < db.ProvisionExpectedSeconds {
		return errors.New("invalid Managed Postgres configuration")
	}
	for _, size := range []string{p.Machines.Control, p.Machines.Ingress, p.Machines.Relay, p.Machines.Pebble, p.Machines.Coordinator, p.Machines.Publisher, p.Machines.Load} {
		if !validFlySlug(size) {
			return errors.New("invalid machine size")
		}
	}
	return nil
}

func decodeJSONFile(path string, value any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
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
func divideRoundUp(value, divisor int) int { return (value + divisor - 1) / divisor }

func writeHumanPlan(w io.Writer, p benchmarkPlan) error {
	var out bytes.Buffer
	fmt.Fprintf(&out, "Benchmark plan (READ ONLY)\nProfile: %s  Suite: %s  Region: %s\n", p.ProfileID, p.Suite, p.Region)
	fmt.Fprintf(&out, "Server: %d control (%s), %d ingress (%s), %dx%d relay (%s)\n", p.Topology.ControlProcesses, p.Machines.Control, p.Topology.IngressProcesses, p.Machines.Ingress, p.Topology.RelayServices, p.Topology.RelayProcessesPerService, p.Machines.Relay)
	fmt.Fprintf(&out, "Database: Managed Postgres %s, PostgreSQL %d, %d GB\nCertificates: %s\n", p.ManagedPostgres.Plan, p.ManagedPostgres.PostgresMajorVersion, p.ManagedPostgres.StorageGB, p.CertificateAuthority)
	if p.CertificateAuthority == benchmarkCertificateAuthorityPebble {
		fmt.Fprintf(&out, "Certificate service: one Pebble Machine (%s)\n", p.Machines.Pebble)
	}
	fmt.Fprintf(&out, "DNS: two temporary Route 53 zones; public addresses for control, ingress, %d relay services, and coordinator\n", p.Topology.RelayServices)
	t := p.Target
	fmt.Fprintf(&out, "Generators: %d publisher (%s), %d visitor (%s), one coordinator (%s)\n", t.PublisherWorkers, p.Machines.Publisher, t.LoadWorkers, p.Machines.Load, p.Machines.Coordinator)
	fmt.Fprintf(&out, "Target: %d public URLs, %d fresh/s, %d held, %d bytes\nVisitors: %d concurrent, %d waiting, 5s request budget\nWindows: %d x %ds, warmup %ds, workload limit %ds\nMaximum run duration: %s\n", t.PublicURLs, t.FreshConnectionsPerSecond, t.HeldStreams, t.PayloadBytes, t.Concurrency, t.QueueSlots, t.Repetitions, t.DurationSeconds, t.WarmupSeconds, t.TimeoutSeconds, time.Duration(p.MaximumDurationSeconds)*time.Second)
	fmt.Fprintln(&out, "Execution creates paid Fly and DNS resources and requires explicit BENCH_SUITE and BENCH_APPROVED=1.")
	_, err := io.Copy(w, &out)
	return err
}
