package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReadRuntimePlan(t *testing.T) {
	// the daemon's setup owns membership; the runner only reads and checks the
	// saved projections. arbitrary names prove it does not select its own roles.
	plan := map[string][]string{
		"services":   {"database", "control", "edge", "relay", "publisher", "visitor", "coordinator"},
		"start":      {"control", "edge", "relay", "publisher", "visitor", "coordinator"},
		"publishers": {"publisher"}, "ingresses": {"edge"},
		"fault-targets": {"relay"},
		"stop-visitors": {"visitor"}, "stop-publishers": {"publisher"},
		"stop-servers": {"edge", "relay"}, "stop-controls": {"control"}, "stop-support": {"coordinator", "database"},
	}
	directory := t.TempDir()
	write := func(t *testing.T, plan map[string][]string) {
		t.Helper()
		data, err := json.Marshal(plan)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "runtime-plan.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(t, plan)
	got, err := readRuntimePlan(directory)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, plan) {
		t.Fatalf("plan changed: %v", got)
	}
	for _, test := range []struct {
		name    string
		change  func(map[string][]string)
		message string
	}{
		{"missing publishers", func(p map[string][]string) { delete(p, "publishers") }, "missing publishers"},
		{"missing fault targets", func(p map[string][]string) { delete(p, "fault-targets") }, "missing fault-targets"},
		{"empty fault targets", func(p map[string][]string) { p["fault-targets"] = nil }, "missing fault-targets"},
		{"missing control stop", func(p map[string][]string) { delete(p, "stop-controls") }, "missing stop-controls"},
		{"duplicate service", func(p map[string][]string) { p["services"] = append(p["services"], "relay") }, "duplicate services"},
		{"omitted shutdown", func(p map[string][]string) { p["stop-servers"] = []string{"edge"} }, "shutdown must cover"},
		{"absent startup", func(p map[string][]string) { p["start"] = append(p["start"], "unused") }, "absent service unused"},
		{"absent fault", func(p map[string][]string) { p["fault-targets"] = []string{"unused"} }, "absent service unused"},
		{"source outside fault", func(p map[string][]string) { p["fault-sources"] = []string{"publisher"} }, "outside the planned fault"},
		{"destination outside fault", func(p map[string][]string) { p["fault-destinations"] = []string{"edge"} }, "outside the planned fault"},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := make(map[string][]string)
			for key, names := range plan {
				copy[key] = append([]string{}, names...)
			}
			test.change(copy)
			write(t, copy)
			if _, err := readRuntimePlan(directory); err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("read plan error=%v, want %q", err, test.message)
			}
		})
	}
}

func TestRuntimeShutdownStageOrder(t *testing.T) {
	want := []string{"stop-visitors", "stop-publishers", "stop-servers", "stop-controls", "stop-support"}
	if !reflect.DeepEqual(runtimeStopStages[:], want) {
		t.Fatalf("shutdown stages=%v, want %v; control must join before PostgreSQL stops", runtimeStopStages, want)
	}
}

func TestReadRuntimePlanRequiresSetupArtifact(t *testing.T) {
	if _, err := readRuntimePlan(t.TempDir()); err == nil {
		t.Fatal("accepted missing plan")
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "runtime-plan.json"), []byte(`{"services":[42]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRuntimePlan(directory); err == nil {
		t.Fatal("accepted invalid plan")
	}
}

func TestRuntimeCommandsRequirePlannedComponents(t *testing.T) {
	h := runtimeHarness{plan: map[string][]string{
		"services":      {"publishers", "publishers-2", "relay-a", "relay-a-2"},
		"fault-targets": {"publishers", "publishers-2", "relay-a"},
	}}
	for _, args := range [][]string{
		{"exec", "-T", "publishers", "ss", "-H", "-uan"},
		{"exec", "-T", "publishers-2", "iptables", "-L"},
		{"kill", "--signal", "SIGKILL", "relay-a"},
		{"start", "relay-a"}, {"stop", "relay-a", "relay-a-2"},
	} {
		if err := h.checkCommandServices(args); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{
		{"exec", "-T", "publishers-3", "ss", "-H", "-uan"},
		{"exec", "-T", "app-3", "ss", "-H", "-uan"},
		{"kill", "--signal", "SIGKILL", "missing-relay"},
		{"start", "missing-relay"}, {"stop", "relay-a", "publishers-4"},
		{"exec", "-T", "relay-a-2", "iptables", "-L"},
	} {
		if err := h.checkCommandServices(args); err == nil {
			t.Fatalf("accepted absent component: %v", args)
		}
	}
}
