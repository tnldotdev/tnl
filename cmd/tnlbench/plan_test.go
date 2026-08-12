package main

import (
	"bytes"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildSmokePlanUsesProductionTopologyAndSafeWorkerRate(t *testing.T) {
	plan, err := repositoryPlanCommand("smoke").build(time.Date(2026, time.September, 16, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ReadOnly || plan.SchemaVersion != 3 || plan.ProfileID != "fly-production-v3" ||
		plan.CertificateAuthority != benchmarkCertificateAuthorityPebble ||
		plan.ManagedPostgres.Plan != "basic" || plan.ManagedPostgres.PostgresMajorVersion != 17 ||
		plan.ManagedPostgres.StorageGB != 10 || plan.Topology.ControlProcesses != 2 ||
		plan.Topology.IngressProcesses != 2 || plan.Topology.RelayServices != 2 ||
		plan.Topology.RelayProcessesPerService != 2 || len(plan.Cells) != 1 {
		t.Fatalf("plan = %#v", plan)
	}
	cell := plan.Cells[0]
	if cell.Routes != 2 || cell.FreshConnectionsPerSecond != 2 || cell.HeldStreams != 2 ||
		cell.PublisherWorkers != 1 || cell.LoadWorkers != 1 || cell.FreshConnectionsPerWorker >= 40 ||
		plan.ExpectedResultRows != 2 || plan.ExpectedDurationSeconds != 560 || plan.MaximumDurationSeconds != 2120 ||
		plan.ExpectedSpendUSD <= 0 || plan.MaximumSpendUSD <= plan.ExpectedSpendUSD {
		t.Fatalf("cell = %#v, plan = %#v", cell, plan)
	}
}

func TestBuildScoutPlanAddsLoadWorkersBeforeSourceLimit(t *testing.T) {
	plan, err := repositoryPlanCommand("scout").build(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Cells) != 19 {
		t.Fatalf("cells = %d", len(plan.Cells))
	}
	if plan.WorkerLimits.RoutesPerChurnRoute != 1 {
		t.Fatalf("routes per churn route = %d, want one independent route per active route", plan.WorkerLimits.RoutesPerChurnRoute)
	}
	axes := make(map[string]int)
	for _, cell := range plan.Cells {
		if cell.FreshConnectionsPerWorker >= 40 {
			t.Fatalf("unsafe worker rate in %#v", cell)
		}
		axes[cell.Axis]++
	}
	wantAxes := map[string]int{"active_routes": 5, "lifecycle_churn": 4, "fresh_connections": 3, "held_streams": 4, "bandwidth": 3}
	if !maps.Equal(axes, wantAxes) {
		t.Fatalf("axes = %v", axes)
	}
	held := plan.Cells[15]
	if held.Axis != "held_streams" || held.PublisherWorkers != 1 || held.LoadWorkers != 4 || held.HeldStreamsPerWorker != 500 {
		t.Fatalf("held-stream cell = %#v", held)
	}
}

func TestProfileTopologyDrivesPricingWithinBounds(t *testing.T) {
	var profile benchmarkProfile
	if err := decodeJSONFile(repositoryPlanCommand("smoke").ProfileFile, &profile); err != nil {
		t.Fatal(err)
	}
	profile.Topology = benchmarkTopology{
		ControlProcesses: 3, IngressProcesses: 4, RelayServices: 3, RelayProcessesPerService: 5,
	}
	if err := validateBenchmarkProfile(profile); err != nil {
		t.Fatal(err)
	}
	got := fixedResourceSpend(profile, int64(time.Hour/time.Second), false)
	want := 5*profile.Pricing.PublicIPv4PerHour +
		(profile.Pricing.ManagedPostgresPlanPerMonthUSD[profile.ManagedPostgres.Plan]+
			float64(profile.ManagedPostgres.StorageGB)*profile.Pricing.ManagedPostgresStorageGBPerMonthUSD+
			float64(profile.WorkerLimits.PublisherMachines*profile.WorkerLimits.PublisherVolumeGB)*profile.Pricing.VolumeGBPerMonthUSD)/(30*24)
	if got < want-0.000001 || got > want+0.000001 {
		t.Fatalf("fixed spend = %f, want %f", got, want)
	}
	profile.Topology.RelayServices = 1
	if err := validateBenchmarkProfile(profile); err == nil {
		t.Fatal("single-relay-service topology was accepted")
	}
	profile.Topology.RelayServices = 2
	profile.WorkerLimits.RoutesPerChurnRoute = 16
	if err := validateBenchmarkProfile(profile); err == nil {
		t.Fatal("churn groups crossing publisher bands were accepted")
	}
}

func TestBuildConfirmPlanRequiresCompleteTarget(t *testing.T) {
	command := repositoryPlanCommand("confirm")
	if _, err := command.build(time.Now()); err == nil || !strings.Contains(err.Error(), "confirm requires") {
		t.Fatalf("missing target error = %v", err)
	}
	command.Routes, command.FreshRate, command.HeldStreams = 500, 30, 1000
	plan, err := command.build(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Cells) != 3 || plan.Cells[2].Repetition != 3 || plan.Cells[2].FreshConnectionsPerWorker >= 40 {
		t.Fatalf("confirm plan = %#v", plan.Cells)
	}
}

func TestPlanHumanOutputStatesReadOnlyPaidBoundary(t *testing.T) {
	var output bytes.Buffer
	if err := repositoryPlanCommand("smoke").run(&output); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Benchmark plan (READ ONLY)", "2 control, 2 ingress, 2x2 relay",
		"Fly Managed Postgres basic, PostgreSQL 17, 10 GB", "Certificates: private Pebble",
		"Estimated spend", "creates paid Fly",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("plan output omitted %q:\n%s", want, output.String())
		}
	}
}

func TestBuildCompatibilityPlanUsesLetsEncrypt(t *testing.T) {
	plan, err := repositoryPlanCommand("compatibility").build(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if plan.CertificateAuthority != benchmarkCertificateAuthorityLetsEncrypt || len(plan.Cells) != 1 ||
		plan.Cells[0].Routes != 1 || !strings.Contains(strings.Join(plan.Warnings, "\n"), "rate limits") {
		t.Fatalf("compatibility plan = %#v", plan)
	}
}

func TestPlanHumanOutputPropagatesWriterError(t *testing.T) {
	want := errors.New("write failed")
	if err := repositoryPlanCommand("smoke").run(errorWriter{err: want}); !errors.Is(err, want) {
		t.Fatalf("plan error = %v, want %v", err, want)
	}
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

func TestDecodeJSONFileRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var profile benchmarkProfile
	if err := decodeJSONFile(path, &profile); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("decode error = %v", err)
	}
}

func repositoryPlanCommand(suite string) planCommand {
	return planCommand{
		Suite: suite, ProfileFile: filepath.Join("..", "..", "benchmarks", "suites", "fly-production.json"), Format: "human",
	}
}
