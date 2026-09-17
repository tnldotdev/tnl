package main

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestParseManagedPostgresCreateOutput(t *testing.T) {
	const name = "tnl-bench-bench-20260916-120000-abcdefgh-pg"
	const pooledURL = "postgresql://fly-user:p%40ss@pgbouncer.cluster.flympg.net/fly-db"
	output := []byte("Selected Plan: Basic\n" +
		"Waiting for cluster " + name + " (mpg_123) to be ready...\n" +
		"Managed Postgres cluster created successfully!\n" +
		"  ID: mpg_123\n" +
		"  Name: " + name + "\n" +
		"  Organization: tnl\n" +
		"  Region: sjc\n" +
		"  Plan: basic\n" +
		"  Disk: 10GB\n" +
		"  Connection string: " + pooledURL + "\n")
	cluster, gotURL := parseManagedPostgresCreateOutput(output, name)
	if cluster.ID != "mpg_123" || cluster.Name != name || cluster.Organization.Slug != "tnl" ||
		cluster.Region != "sjc" || cluster.Plan != "basic" || cluster.StorageGB != 10 || gotURL != pooledURL {
		t.Fatalf("cluster = %#v, URL = %q", cluster, gotURL)
	}
}

func TestManagedPostgresURLsUsePooledRuntimeAndDirectMigrationHosts(t *testing.T) {
	pooled, direct, err := managedPostgresURLs(
		"postgresql://fly-user:p%40ss@pgbouncer.cluster.flympg.net/fly-db?connect_timeout=5",
	)
	if err != nil {
		t.Fatal(err)
	}
	if pooled != "postgresql://fly-user:p%40ss@pgbouncer.cluster.flympg.net/fly-db?connect_timeout=5" ||
		direct != "postgresql://fly-user:p%40ss@direct.cluster.flympg.net/fly-db?connect_timeout=5" {
		t.Fatalf("pooled = %q, direct = %q", pooled, direct)
	}
	for _, invalid := range []string{
		"", "https://user:pass@pgbouncer.cluster.flympg.net/fly-db",
		"postgres://user@pgbouncer.cluster.flympg.net/fly-db",
		"postgres://user:pass@direct.cluster.flympg.net/fly-db",
	} {
		if _, _, err := managedPostgresURLs(invalid); err == nil {
			t.Fatalf("invalid URL %q was accepted", invalid)
		}
	}
}

func TestFlyCreateManagedPostgresUsesExplicitConfiguration(t *testing.T) {
	const name = "tnl-bench-bench-20260916-120000-abcdefgh-pg"
	executor := &executorStub{responses: [][]byte{[]byte(
		"Waiting for cluster " + name + " (mpg_123) to be ready...\n" +
			"ID: mpg_123\nName: " + name + "\nOrganization: tnl\nRegion: sjc\nPlan: basic\nDisk: 10GB\n" +
			"Connection string: postgresql://user:secret@pgbouncer.cluster.flympg.net/fly-db\n",
	)}}
	platform := flyPlatform{binary: "flyctl", org: "tnl", region: "sjc", executor: executor}
	cluster, credentials, err := platform.createManagedPostgres(t.Context(), name, benchmarkManagedPostgres{
		Plan: "basic", PostgresMajorVersion: 17, StorageGB: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"mpg", "create", "--name", name, "--org", "tnl", "--region", "sjc", "--plan", "basic",
		"--volume-size", "10", "--pg-major-version", "17",
	}
	if cluster.ID != "mpg_123" || !strings.Contains(credentials.PooledURL, "@pgbouncer.") ||
		!strings.Contains(credentials.DirectURL, "@direct.") || len(executor.calls) != 1 ||
		!slices.Equal(executor.calls[0].args, want) {
		t.Fatalf("cluster = %#v, credentials = %#v, calls = %#v", cluster, credentials, executor.calls)
	}
}

func TestManagedPostgresErrorsRedactDatabaseURLs(t *testing.T) {
	err := redactManagedPostgresError(errors.New(
		`failed after postgresql://fly-user:super-secret@pgbouncer.cluster.flympg.net/fly-db {"password":"other-secret"}`,
	))
	if strings.Contains(err.Error(), "super-secret") || strings.Contains(err.Error(), "other-secret") ||
		!strings.Contains(err.Error(), "[REDACTED_DATABASE_URL]") || !strings.Contains(err.Error(), `"password":"[REDACTED]"`) {
		t.Fatalf("redacted error = %v", err)
	}
}

func TestFlyListManagedPostgresDecodesFlyJSON(t *testing.T) {
	executor := &executorStub{responses: [][]byte{[]byte(`[{"Id":"mpg_123","Name":"benchmark-pg","Status":"ready","Plan":"basic","Region":"sjc","Organization":{"Slug":"tnl"},"Disk":10}]`)}}
	platform := flyPlatform{binary: "flyctl", org: "tnl", executor: executor}
	clusters, err := platform.listManagedPostgres(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(clusters) != 1 || clusters[0].ID != "mpg_123" || clusters[0].Organization.Slug != "tnl" || clusters[0].StorageGB != 10 {
		t.Fatalf("clusters = %#v", clusters)
	}
	if len(executor.calls) != 1 || !slices.Equal(executor.calls[0].args, []string{"mpg", "list", "--org", "tnl", "--json"}) {
		t.Fatalf("calls = %#v", executor.calls)
	}
}

func TestFlyManagedPostgresStatusReturnsOnlyClusterDetails(t *testing.T) {
	executor := &executorStub{responses: [][]byte{[]byte(`{
		"data":{"id":"mpg_123","name":"benchmark-pg","status":"ready","plan":"basic","region":"sjc","disk":10},
		"credentials":{"user":"fly-user","password":"super-secret","pgbouncer_uri":"postgresql://fly-user:super-secret@pgbouncer.cluster.flympg.net/fly-db"}
	}`)}}
	platform := flyPlatform{binary: "flyctl", executor: executor}
	cluster, err := platform.managedPostgresStatus(t.Context(), "mpg_123")
	if err != nil {
		t.Fatal(err)
	}
	if cluster.ID != "mpg_123" || cluster.Name != "benchmark-pg" || cluster.StorageGB != 10 {
		t.Fatalf("cluster = %#v", cluster)
	}
	if len(executor.calls) != 1 || !slices.Equal(executor.calls[0].args, []string{"mpg", "status", "mpg_123", "--json"}) {
		t.Fatalf("calls = %#v", executor.calls)
	}
}

func TestSelectManagedPostgresForCleanupRequiresExactOwnership(t *testing.T) {
	expected := manifestManagedPostgres{
		ID: "mpg_123", Name: "tnl-bench-bench-20260916-120000-abcdefgh-pg", Region: "sjc", Plan: "basic", StorageGB: 10,
	}
	cluster := flyManagedPostgresCluster{
		ID: expected.ID, Name: expected.Name, Region: expected.Region, Plan: expected.Plan,
		Organization: flyManagedPostgresOrganization{Slug: "tnl"},
	}
	if got, found, err := selectManagedPostgresForCleanup(expected, "tnl", []flyManagedPostgresCluster{cluster}); err != nil || !found || got.ID != expected.ID {
		t.Fatalf("cluster = %#v, found = %t, err = %v", got, found, err)
	}
	expected.ID = ""
	if got, found, err := selectManagedPostgresForCleanup(expected, "tnl", []flyManagedPostgresCluster{cluster}); err != nil || !found || got.ID != cluster.ID {
		t.Fatalf("recovered cluster = %#v, found = %t, err = %v", got, found, err)
	}
	cluster.Organization.Slug = "other"
	if _, _, err := selectManagedPostgresForCleanup(expected, "tnl", []flyManagedPostgresCluster{cluster}); err == nil {
		t.Fatal("cleanup accepted a cluster from another organization")
	}
}
