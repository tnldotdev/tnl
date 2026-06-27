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

func TestBuildSmokePlan(t *testing.T) {
	command := repositoryPlanCommand("smoke")
	plan, err := command.build(time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !plan.ReadOnly || plan.Transport != "auto" || plan.Workload.Classification != "assumed" {
		t.Fatalf("plan metadata = %#v", plan)
	}
	if plan.SchemaVersion != 2 || len(plan.Cells) != 1 || plan.Cells[0].Relays != 2 || plan.Cells[0].Routes != 25 || plan.Cells[0].Drivers != 1 {
		t.Fatalf("cells = %#v", plan.Cells)
	}
	if plan.ExpectedResultRows != 1 || plan.ExpectedSpend.TotalUSD <= 0 ||
		plan.MaximumSpend.TotalUSD <= plan.ExpectedSpend.TotalUSD {
		t.Fatalf("plan totals = rows %d, expected $%f, maximum $%f",
			plan.ExpectedResultRows, plan.ExpectedSpend.TotalUSD, plan.MaximumSpend.TotalUSD)
	}
}

func TestBuildScalePlanRequiresAndUsesSchedulingTarget(t *testing.T) {
	command := repositoryPlanCommand("scale")
	if _, err := command.build(time.Now()); err == nil || !strings.Contains(err.Error(), "qualified scheduling target") {
		t.Fatalf("missing target error = %v", err)
	}
	command.ConnectionsPerRelay = 300
	plan, err := command.build(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Cells) != 12 || plan.Cells[len(plan.Cells)-1].Routes != 1500 || plan.ExpectedResultRows != 27 {
		t.Fatalf("scale plan = %d cells, final %#v, %d rows", len(plan.Cells), plan.Cells[len(plan.Cells)-1], plan.ExpectedResultRows)
	}
}

func TestPlanHumanOutputLabelsAssumptions(t *testing.T) {
	command := repositoryPlanCommand("smoke")
	var output bytes.Buffer
	if err := command.run(&output); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{"Benchmark plan (READ ONLY)", "WORKLOAD ASSUMPTIONS (NOT OBSERVED)", "Expected spend", "Required inputs"} {
		if !strings.Contains(text, want) {
			t.Fatalf("plan output omitted %q:\n%s", want, text)
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

func TestDecodeProfileRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var profile workloadProfile
	if err := decodeProfile(path, &profile); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("decode error = %v", err)
	}
}

func repositoryPlanCommand(suite string) planCommand {
	return planCommand{
		Suite:        suite,
		ProfileFile:  filepath.Join("..", "..", "benchmarks", "suites", "p1-horizontal.json"),
		WorkloadFile: filepath.Join("..", "..", "benchmarks", "workloads", "agent-worktrees-assumed-v1.json"),
		PricingFile:  filepath.Join("..", "..", "benchmarks", "pricing", "fly-sjc.json"),
		Format:       "human",
	}
}
