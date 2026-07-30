package main

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRunValidationRequiresBothPaidResourceGates(t *testing.T) {
	valid := runCommand{
		Suite: "smoke", Approved: "1", FlyOrg: "example", ParentDomain: "bench.example.com",
		ParentZoneID: "Z0123456789", ACMEEmail: "operator@example.com", ResultsRoot: t.TempDir(),
	}
	t.Setenv("BENCH_SUITE", "smoke")
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*runCommand){
		"approval": func(command *runCommand) { command.Approved = "true" },
		"suite":    func(command *runCommand) { t.Setenv("BENCH_SUITE", "") },
		"domain":   func(command *runCommand) { command.ParentDomain = "Bench.example.com" },
		"zone":     func(command *runCommand) { command.ParentZoneID = "/hostedzone/Z123" },
	} {
		t.Run(name, func(t *testing.T) {
			command := valid
			mutate(&command)
			if err := command.Validate(); err == nil {
				t.Fatal("invalid run command was accepted")
			}
		})
	}
}

func TestManifestContainsNoGeneratedSecrets(t *testing.T) {
	secrets, err := generateRunSecrets()
	if err != nil {
		t.Fatal(err)
	}
	manifest := runManifest{
		SchemaVersion: runManifestSchemaVersion, RunID: "bench-20260916-120000-abcdefgh",
		ParentDomain: "bench.example.com", ParentZoneID: "Z123",
		ServerDomain:  "bench-20260916-120000-abcdefgh.bench.example.com",
		ManagedDomain: "routes.bench-20260916-120000-abcdefgh.bench.example.com",
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		secrets.LoginToken, secrets.ClusterSecret, secrets.StorageKey, secrets.DatabasePassword, secrets.CoordinatorToken,
	} {
		if strings.Contains(string(data), secret) {
			t.Fatal("manifest serialized a generated secret")
		}
	}
}

func TestManifestCleanupOwnershipChecks(t *testing.T) {
	manifest := runManifest{
		SchemaVersion: runManifestSchemaVersion, RunID: "bench-20260916-120000-abcdefgh",
		ParentDomain: "bench.example.com", ParentZoneID: "Z123",
		ServerDomain:  "bench-20260916-120000-abcdefgh.bench.example.com",
		ManagedDomain: "routes.bench-20260916-120000-abcdefgh.bench.example.com",
		Apps:          []manifestApp{{Role: "control", Name: "tnl-bench-bench-20260916-120000-abcdefgh-ctl"}},
		Zones: []manifestZone{{
			Kind: "server", Name: "bench-20260916-120000-abcdefgh.bench.example.com", ID: "ZSERVER",
			ParentName: "bench.example.com", ParentZoneID: "Z123",
			NameServers: []string{"ns-1.example.net", "ns-2.example.net"},
		}},
	}
	if err := validateManifestResources(manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Apps[0].Name = "production-control"
	if err := validateManifestResources(manifest); err == nil {
		t.Fatal("cleanup accepted an app outside the run prefix")
	}
}

func TestBalancedAssignmentPreservesTotals(t *testing.T) {
	for _, test := range []struct{ total, workers int }{{1, 4}, {80, 3}, {1000, 4}} {
		sum, minimum, maximum := 0, test.total, 0
		for index := range test.workers {
			value := balancedAssignment(test.total, test.workers, index)
			sum += value
			minimum, maximum = min(minimum, value), max(maximum, value)
		}
		if sum != test.total || maximum-minimum > 1 {
			t.Fatalf("assignment %d/%d = total %d, range %d..%d", test.total, test.workers, sum, minimum, maximum)
		}
	}
}

func TestRunIDIsDNSAndAppSafe(t *testing.T) {
	runID, err := newRunID(time.Date(2026, time.September, 16, 12, 34, 56, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(runID, "bench-20260916-123456-") || strings.ContainsAny(runID, "_ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		t.Fatalf("run ID = %q", runID)
	}
	if !validRunID(runID) {
		t.Fatalf("generated run ID %q is not valid", runID)
	}
	for role, app := range benchmarkAppNames(runID) {
		if len(app) > 63 || !strings.HasPrefix(app, "tnl-bench-"+runID+"-") {
			t.Fatalf("%s app = %q", role, app)
		}
	}
}

func TestValidRunIDRejectsNonGeneratedValues(t *testing.T) {
	for _, value := range []string{
		"production", "bench-20260916-123456-short", "bench-20261316-123456-abcdefgh",
		"bench-20260916-123456-ABCDefgh", "bench-20260916-123456-abcd_efg",
	} {
		if validRunID(value) {
			t.Fatalf("run ID %q was accepted", value)
		}
	}
}

func TestCleanupRunSkipsRemovedAppsAndPersistsProgress(t *testing.T) {
	runID := "bench-20260916-120000-abcdefgh"
	apps := benchmarkAppNames(runID)
	manifest := runManifest{
		SchemaVersion: runManifestSchemaVersion, RunID: runID, Status: "cleanup_failed",
		ParentDomain: "bench.example.com", ParentZoneID: "Z123",
		ServerDomain: runID + ".bench.example.com", ManagedDomain: "routes." + runID + ".bench.example.com",
		Apps: []manifestApp{
			{Role: "postgres", Name: apps["postgres"], Removed: true},
			{Role: "control", Name: apps["control"]},
		},
	}
	executor := new(executorStub)
	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	if err := cleanupRun(t.Context(), flyPlatform{binary: "fly", executor: executor}, benchmarkDNS{}, manifestPath, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Status != "cleaned" || !manifest.Apps[1].Removed || len(executor.calls) != 1 {
		t.Fatalf("manifest = %#v, calls = %#v", manifest, executor.calls)
	}
	if got := executor.calls[0].args; !slices.Equal(got, []string{"apps", "destroy", apps["control"], "--yes"}) {
		t.Fatalf("destroy arguments = %v", got)
	}
	loaded, err := loadManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Status != "cleaned" || !loaded.Apps[1].Removed {
		t.Fatalf("persisted manifest = %#v", loaded)
	}
}
