package main

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestRunValidationRequiresBothPaidResourceGates(t *testing.T) {
	valid := runCommand{
		workloadOptions: workloadOptions{Suite: "smoke"}, Approved: "1", FlyOrg: "example", ParentDomain: "bench.example.com",
		ParentZoneID: "Z0123456789", ACMEEmail: "operator@example.com", ResultsRoot: t.TempDir(),
	}
	t.Setenv("BENCH_SUITE", "smoke")
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*runCommand){
		"approval": func(command *runCommand) { command.Approved = "true" },
		"suite":    func(command *runCommand) { t.Setenv("BENCH_SUITE", "") },
		"fly org":  func(command *runCommand) { command.FlyOrg = "Example Org" },
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

func TestBenchmarkAWSConfigRejectsExpiringCredentialSnapshot(t *testing.T) {
	deadline := time.Now().Add(2 * time.Hour)
	credentials := aws.Credentials{CanExpire: true, Expires: time.Now().Add(time.Hour)}
	if err := validateBenchmarkAWSCredentials(credentials, "", deadline); err == nil {
		t.Fatal("expired control credential snapshot was accepted")
	}
	if err := validateBenchmarkAWSCredentials(credentials, "arn:aws:iam::123456789012:role/bench", deadline); err != nil {
		t.Fatalf("renewable role was rejected: %v", err)
	}
	credentials.CanExpire = false
	if err := validateBenchmarkAWSCredentials(credentials, "", deadline); err != nil {
		t.Fatalf("long-lived credentials were rejected: %v", err)
	}
}

func TestBenchmarkProgressIncludesElapsedTime(t *testing.T) {
	startedAt := time.Date(2026, time.September, 18, 2, 0, 0, 0, time.UTC)
	var output strings.Builder
	progress := &benchmarkProgress{
		output: &output, startedAt: startedAt,
		now: func() time.Time { return startedAt.Add(time.Minute + 5*time.Second + 900*time.Millisecond) },
	}
	progress.printf("database: ready")
	if got, want := output.String(), "[+1m5s] database: ready\n"; got != want {
		t.Fatalf("progress = %q, want %q", got, want)
	}
}

func TestManifestContainsNoGeneratedSecrets(t *testing.T) {
	secrets, err := generateRunSecrets()
	if err != nil {
		t.Fatal(err)
	}
	manifest := runManifest{
		SchemaVersion: runManifestSchemaVersion, RunID: "bench-20260916-120000-abcdefgh",
		FlyOrg: "example", Region: "sjc", Topology: testTopology(), ParentDomain: "bench.example.com", ParentZoneID: "Z123",
		CertificateAuthority: benchmarkCertificateAuthorityPebble,
		ServerDomain:         "bench-20260916-120000-abcdefgh.bench.example.com",
		ManagedDomain:        "public-urls.bench-20260916-120000-abcdefgh.bench.example.com",
		ManagedPostgres:      testManifestManagedPostgres("bench-20260916-120000-abcdefgh"),
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{
		secrets.LoginToken, secrets.ClusterSecret, secrets.StorageKey, secrets.CoordinatorToken,
	} {
		if strings.Contains(string(data), secret) {
			t.Fatal("manifest serialized a generated secret")
		}
	}
}

func TestManifestCleanupOwnershipChecks(t *testing.T) {
	manifest := runManifest{
		SchemaVersion: runManifestSchemaVersion, RunID: "bench-20260916-120000-abcdefgh",
		FlyOrg: "example", Region: "sjc", Topology: testTopology(), ParentDomain: "bench.example.com", ParentZoneID: "Z123",
		CertificateAuthority: benchmarkCertificateAuthorityPebble,
		ServerDomain:         "bench-20260916-120000-abcdefgh.bench.example.com",
		ManagedDomain:        "public-urls.bench-20260916-120000-abcdefgh.bench.example.com",
		ManagedPostgres:      testManifestManagedPostgres("bench-20260916-120000-abcdefgh"),
		Apps:                 []manifestApp{{Role: "control", Name: "tnl-bench-bench-20260916-120000-abcdefgh-ctl"}},
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
	for role, app := range benchmarkAppNames(runID, 2) {
		if len(app) > 63 || !strings.HasPrefix(app, "tnl-bench-"+runID+"-") {
			t.Fatalf("%s app = %q", role, app)
		}
	}
	if database := benchmarkDatabaseName(runID); len(database) > 63 || !strings.HasPrefix(database, "tnl-bench-"+runID+"-") {
		t.Fatalf("Managed Postgres database name = %q", database)
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

func TestBenchmarkAppNamesFollowRelayServiceCount(t *testing.T) {
	runID := "bench-20260916-120000-abcdefgh"
	roles := benchmarkRelayRoles(3)
	if !slices.Equal(roles, []string{"relay-a", "relay-b", "relay-c"}) {
		t.Fatalf("relay roles = %v", roles)
	}
	apps := benchmarkAppNames(runID, 3)
	if len(apps) != 9 || apps["relay-c"] != "tnl-bench-"+runID+"-rc" {
		t.Fatalf("apps = %v", apps)
	}
}

func TestCleanupRunSkipsRemovedAppsAndPersistsProgress(t *testing.T) {
	runID := "bench-20260916-120000-abcdefgh"
	apps := benchmarkAppNames(runID, 2)
	manifest := runManifest{
		SchemaVersion: runManifestSchemaVersion, RunID: runID, Status: "cleanup_failed",
		FlyOrg: "example", Region: "sjc", Topology: testTopology(), ParentDomain: "bench.example.com", ParentZoneID: "Z123",
		CertificateAuthority: benchmarkCertificateAuthorityPebble,
		ServerDomain:         runID + ".bench.example.com", ManagedDomain: "public-urls." + runID + ".bench.example.com",
		ManagedPostgres: testManifestManagedPostgres(runID),
		Apps:            []manifestApp{{Role: "control", Name: apps["control"]}},
	}
	executor := new(executorStub)
	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	if err := cleanupRun(
		t.Context(), flyPlatform{binary: "fly", executor: executor},
		benchmarkDNS{}, manifestPath, &manifest, nil,
	); err != nil {
		t.Fatal(err)
	}
	if manifest.Status != "cleaned" || !manifest.Apps[0].Removed || !manifest.ManagedPostgres.Removed || len(executor.calls) != 1 {
		t.Fatalf("manifest = %#v, calls = %#v", manifest, executor.calls)
	}
	if got := executor.calls[0].args; !slices.Equal(got, []string{"apps", "destroy", apps["control"], "--yes"}) {
		t.Fatalf("destroy arguments = %v", got)
	}
	loaded, err := loadManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Status != "cleaned" || !loaded.Apps[0].Removed || !loaded.ManagedPostgres.Removed {
		t.Fatalf("persisted manifest = %#v", loaded)
	}
}

func TestCleanupRunDestroysControlBeforeManagedPostgres(t *testing.T) {
	runID := "bench-20260916-120000-abcdefgh"
	apps := benchmarkAppNames(runID, 2)
	database := testManifestManagedPostgres(runID)
	database.CreationStarted = true
	database.ID = "mpg_123"
	live := flyManagedPostgresCluster{
		ID: database.ID, Name: database.Name, Region: database.Region, Plan: database.Plan, StorageGB: database.StorageGB,
		Organization: flyManagedPostgresOrganization{Slug: "example"},
	}
	databases, err := json.Marshal([]flyManagedPostgresCluster{live})
	if err != nil {
		t.Fatal(err)
	}
	status, err := json.Marshal(struct {
		Data flyManagedPostgresCluster `json:"data"`
	}{Data: live})
	if err != nil {
		t.Fatal(err)
	}
	flyExecutor := &executorStub{responses: [][]byte{
		nil, databases, status, nil, []byte(`[]`),
	}}
	manifest := runManifest{
		SchemaVersion: runManifestSchemaVersion, RunID: runID, Status: "cleanup_failed", FlyOrg: "example", Region: "sjc", Topology: testTopology(),
		CertificateAuthority: benchmarkCertificateAuthorityPebble,
		ParentDomain:         "bench.example.com", ParentZoneID: "Z123", ServerDomain: runID + ".bench.example.com",
		ManagedDomain: "public-urls." + runID + ".bench.example.com", ManagedPostgres: database,
		Apps: []manifestApp{{Role: "control", Name: apps["control"]}},
	}
	manifestPath := filepath.Join(t.TempDir(), "manifest.json")
	if err := cleanupRun(
		t.Context(), flyPlatform{binary: "fly", org: "example", executor: flyExecutor},
		benchmarkDNS{}, manifestPath, &manifest, nil,
	); err != nil {
		t.Fatal(err)
	}
	if len(flyExecutor.calls) != 5 || flyExecutor.calls[0].args[0] != "apps" ||
		!slices.Equal(flyExecutor.calls[3].args, []string{"mpg", "destroy", database.ID, "--yes"}) ||
		!manifest.ManagedPostgres.Removed {
		t.Fatalf("manifest = %#v, Fly calls = %#v", manifest, flyExecutor.calls)
	}
}

func TestCleanupRunPreservesManagedPostgresWhenControlRemovalFails(t *testing.T) {
	runID := "bench-20260916-120000-abcdefgh"
	database := testManifestManagedPostgres(runID)
	database.CreationStarted = true
	manifest := runManifest{
		SchemaVersion: runManifestSchemaVersion, RunID: runID, Status: "cleanup_failed", FlyOrg: "example", Region: "sjc", Topology: testTopology(),
		CertificateAuthority: benchmarkCertificateAuthorityPebble,
		ParentDomain:         "bench.example.com", ParentZoneID: "Z123", ServerDomain: runID + ".bench.example.com",
		ManagedDomain: "public-urls." + runID + ".bench.example.com", ManagedPostgres: database,
		Apps: []manifestApp{{Role: "control", Name: benchmarkAppNames(runID, 2)["control"]}},
	}
	executor := &executorStub{errs: []error{errors.New("destroy failed")}}
	err := cleanupRun(
		t.Context(), flyPlatform{binary: "fly", org: "example", executor: executor},
		benchmarkDNS{}, filepath.Join(t.TempDir(), "manifest.json"), &manifest, nil,
	)
	if err == nil || len(executor.calls) != 1 || manifest.ManagedPostgres.Removed || manifest.Status != "cleanup_failed" {
		t.Fatalf("manifest = %#v, calls = %#v, error = %v", manifest, executor.calls, err)
	}
}

func TestDiscoverManagedPostgresForCleanupRetriesInterruptedCreationByName(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		expected := *testManifestManagedPostgres("bench-20260916-120000-abcdefgh")
		database := flyManagedPostgresCluster{
			ID: "mpg_123", Name: expected.Name, Region: expected.Region, Plan: expected.Plan,
			Organization: flyManagedPostgresOrganization{Slug: "example"},
		}
		databases, err := json.Marshal([]flyManagedPostgresCluster{database})
		if err != nil {
			t.Fatal(err)
		}
		executor := &executorStub{responses: [][]byte{
			[]byte(`[]`), databases,
		}}
		got, found, err := discoverManagedPostgresForCleanup(
			t.Context(), flyPlatform{binary: "fly", org: "example", executor: executor}, expected, "example",
		)
		if err != nil || !found || got.Name != database.Name || len(executor.calls) != 2 {
			t.Fatalf("database = %#v, found = %t, calls = %#v, error = %v", got, found, executor.calls, err)
		}
	})
}

func TestControlProvisionFailurePersistsRedactedDiagnostics(t *testing.T) {
	directory := t.TempDir()
	manifestPath := filepath.Join(directory, "manifest.json")
	executor := &executorStub{responses: [][]byte{
		[]byte("TOKEN=login-secret"),
		[]byte(`database postgresql://fly-user:database-secret@pgbouncer.cluster.flympg.net/fly-db {"password":"json-secret"}`),
	}}
	err := controlProvisionFailure(
		flyPlatform{binary: "fly", executor: executor}, manifestPath, "control-app",
		[]flyMachine{{ID: "machine-1", Name: "control-1"}},
		runSecrets{LoginToken: "login-secret"},
		flyManagedPostgresCredentials{
			PooledURL: "postgresql://fly-user:database-secret@pgbouncer.cluster.flympg.net/fly-db",
		},
		errors.New("not ready"),
	)
	if err == nil || !strings.Contains(err.Error(), "diagnostics/control.txt") {
		t.Fatalf("error = %v", err)
	}
	data, readErr := os.ReadFile(filepath.Join(directory, "diagnostics", "control.txt"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	text := string(data)
	for _, secret := range []string{"login-secret", "database-secret", "json-secret"} {
		if strings.Contains(text, secret) {
			t.Fatalf("diagnostics contain %q: %s", secret, text)
		}
	}
}

func TestWaitHTTPSReadyUsesBenchmarkTrustRoots(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := waitHTTPSReady(t.Context(), server.URL, string(root), time.Second); err != nil {
		t.Fatal(err)
	}
	if err := waitHTTPSReady(t.Context(), server.URL, "not a certificate", 0); err == nil {
		t.Fatal("invalid benchmark trust roots were accepted")
	}
}

func testManifestManagedPostgres(runID string) *manifestManagedPostgres {
	return &manifestManagedPostgres{
		Name: benchmarkDatabaseName(runID), Region: "sjc", Plan: "basic", PostgresMajorVersion: 17, StorageGB: 10,
	}
}

func testTopology() benchmarkTopology {
	return benchmarkTopology{ControlProcesses: 2, IngressProcesses: 2, RelayServices: 2, RelayProcessesPerService: 2}
}
