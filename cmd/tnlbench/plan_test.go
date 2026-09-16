package main

import (
	"bytes"
	"errors"
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
	if !plan.ReadOnly || plan.SchemaVersion != 1 || plan.Topology.ControlProcesses != 2 ||
		plan.Topology.IngressProcesses != 2 || plan.Topology.RelayServices != 2 ||
		plan.Topology.RelayProcessesPerService != 2 || len(plan.Cells) != 1 {
		t.Fatalf("plan = %#v", plan)
	}
	cell := plan.Cells[0]
	if cell.Routes != 2 || cell.FreshConnectionsPerSecond != 2 || cell.HeldStreams != 2 ||
		cell.PublisherWorkers != 1 || cell.LoadWorkers != 1 || cell.FreshConnectionsPerWorker >= 40 ||
		plan.ExpectedResultRows != 2 || plan.ExpectedSpendUSD <= 0 || plan.MaximumSpendUSD <= plan.ExpectedSpendUSD {
		t.Fatalf("cell = %#v, plan = %#v", cell, plan)
	}
}

func TestBuildScoutPlanAddsLoadWorkersBeforeSourceLimit(t *testing.T) {
	plan, err := repositoryPlanCommand("scout").build(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Cells) != 5 {
		t.Fatalf("cells = %d", len(plan.Cells))
	}
	for _, cell := range plan.Cells {
		if cell.FreshConnectionsPerWorker >= 40 {
			t.Fatalf("unsafe worker rate in %#v", cell)
		}
	}
	last := plan.Cells[len(plan.Cells)-1]
	if last.PublisherWorkers != 4 || last.LoadWorkers != 4 || last.HeldStreamsPerWorker != 500 {
		t.Fatalf("last cell = %#v", last)
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
	for _, want := range []string{"Benchmark plan (READ ONLY)", "2 control, 2 ingress, 2x2 relay", "Estimated spend", "creates paid Fly"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("plan output omitted %q:\n%s", want, output.String())
		}
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
