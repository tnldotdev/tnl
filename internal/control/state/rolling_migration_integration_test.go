package state

import (
	"fmt"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationPostgresRollingMigration(t *testing.T) {
	d, directURL, now := newControlStateIntegrationDatabaseWithURL(t, "rolling_migration")
	ctx := t.Context()
	actor := seedControlServiceAuthority(t, d, now, "rolling")
	create := func(name string) ServiceRecord {
		t.Helper()
		service, err := d.CreateServiceAt(ctx, actor.TeamID, actor.ActingIdentityID, name, name,
			ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return service
	}
	checkRead := func(db *Database, want ServiceRecord) {
		t.Helper()
		got, err := db.GetService(ctx, want.ID, actor.ActingIdentityID)
		if err != nil || got.ID != want.ID || got.Name != want.Name || got.TeamID != want.TeamID {
			t.Fatalf("read service %s: got %v, %v", want.Name, got, err)
		}
	}

	before := create("before-migration")
	checkRead(d, before) // prime the old pool's prepared read and write statements.
	if err := d.Readiness(ctx); err != nil {
		t.Fatal(err)
	}
	connections := d.pool.Stat().NewConnsCount()

	// apply a future migration over a separate direct connection. goose commits
	// the additive DDL and its history entry together, as it does in tnld migrate.
	cfg, err := parseDirectConfig(directURL)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB := stdlib.OpenDB(*cfg)
	defer sqlDB.Close()
	futureVersion := minimumSchemaVersion + 1
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, fstest.MapFS{
		fmt.Sprintf("%05d_add_service_note.sql", futureVersion): {Data: []byte(`-- +goose Up
SET LOCAL lock_timeout = '2s';
ALTER TABLE control.services ADD COLUMN future_note text NOT NULL DEFAULT '';
`)},
	}, goose.WithTableName(versionTable), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal(err)
	}
	if err := d.Readiness(ctx); err != nil {
		t.Fatal("open pool stopped being ready after additive migration", err)
	}
	checkRead(d, before)
	after := create("after-migration")
	checkRead(d, after)
	if got := d.pool.Stat().NewConnsCount(); got != connections {
		t.Fatalf("old queries did not survive on the existing connections: opened %d new connections", got-connections)
	}
	if _, err := sqlDB.ExecContext(ctx, `UPDATE control.services SET future_note = 'new value' WHERE id = $1`, before.ID); err != nil {
		t.Fatal(err)
	}

	history := func() string {
		t.Helper()
		var rows string
		if err := sqlDB.QueryRowContext(ctx, `SELECT jsonb_agg(v ORDER BY id)::text FROM control.goose_db_version v`).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		return rows
	}
	if version, err := readSchemaVersion(ctx, d.pool); err != nil || version != futureVersion {
		t.Fatalf("fixture schema version = %d, want %d: %v", version, futureVersion, err)
	}
	newHistory := history()
	if err := Migrate(ctx, directURL); err != nil {
		t.Fatal("older migrate did not accept newer compatible schema", err)
	}
	if history() != newHistory {
		t.Fatal("older migrate changed newer migration history")
	}
	for _, want := range []struct{ id, note string }{{before.ID, "new value"}, {after.ID, ""}} {
		var note string
		if err := sqlDB.QueryRowContext(ctx, `SELECT future_note FROM control.services WHERE id = $1`, want.id).Scan(&note); err != nil || note != want.note {
			t.Fatalf("future column on %s = %q, want %q: %v", want.id, note, want.note, err)
		}
	}

	d.Close()
	restarted, err := Open(ctx, directURL, testStorageKey, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal("older serving binary could not reopen newer schema", err)
	}
	defer restarted.Close()
	if err := restarted.Readiness(ctx); err != nil {
		t.Fatal(err)
	}
	checkRead(restarted, before)
	checkRead(restarted, after)

	// a higher version does not excuse an incompatible baseline.
	if _, err := sqlDB.ExecContext(ctx, `ALTER TABLE control.operator_nameserver_hostnames RENAME TO unsupported_nameserver_layout`); err != nil {
		t.Fatal(err)
	}
	const baselineError = "incompatible version 1 database schema"
	if err := restarted.Readiness(ctx); err == nil || !strings.Contains(err.Error(), baselineError) {
		t.Fatal("readiness did not reject the incompatible baseline", err)
	}
	if db, err := Open(ctx, directURL, testStorageKey, "", naming.ManagedURLModeGenerated); err == nil || !strings.Contains(err.Error(), baselineError) {
		db.Close()
		t.Fatal("open did not reject the incompatible baseline", err)
	}
	if err := Migrate(ctx, directURL); err == nil || !strings.Contains(err.Error(), baselineError) {
		t.Fatal("older migrate did not reject the incompatible baseline", err)
	}
	if history() != newHistory {
		t.Fatal("baseline rejection changed migration history")
	}
}
