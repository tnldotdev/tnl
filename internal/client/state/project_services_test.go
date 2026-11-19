package state

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestProjectServiceInventoryMigrationPreservesExistingRows(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "migration.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	source := clientMigrationFixture(t)
	v1 := fstest.MapFS{"00001_schema.sql": source["00001_schema.sql"]}
	if err := migrateClientSQLite(ctx, db, v1, 1); err != nil {
		t.Fatal(err)
	}
	const server = "https://control.example.test"
	const original = "svc_0123456789abcdefghijkl"
	if _, err := db.ExecContext(ctx, `INSERT INTO server_profiles(origin, created_at, last_used_at) VALUES (?, 1, 1)`, server); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO project_service_inventory VALUES ('/project', ?, ?, 1)`, server, original); err != nil {
		t.Fatal(err)
	}
	if err := migrateClientSQLite(ctx, db, source, schemaVersion); err != nil {
		t.Fatal(err)
	}
	var got string
	if err := db.QueryRowContext(ctx, `SELECT service_id FROM project_service_inventory WHERE project_root='/project' AND server_origin=?`, server).Scan(&got); err != nil || got != original {
		t.Fatalf("existing service not preserved: %q, %v", got, err)
	}
}

func TestKnownProjectServicesSurviveTunnelStopUntilExpiry(t *testing.T) {
	db, err := OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), OpenOptions{Protection: ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const server = "https://control.example.test"
	const first = "svc_0123456789abcdefghijkl"
	options := BeginTunnelOptions{Command: TunnelCommandPublish, Server: server, Project: project, ServiceID: first, Target: "http://127.0.0.1:3000", ServiceProtocol: controlv1.ServiceProtocolHTTP}
	tunnel, err := db.BeginTunnel(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnel.Finish(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	ids, err := db.KnownProjectServices(t.Context(), project, server)
	if err != nil || len(ids) != 1 || ids[0] != first {
		t.Fatalf("stopped tunnel lost saved service: %v, %v", ids, err)
	}
	for _, selection := range []struct{ project, server string }{{t.TempDir(), server}, {project, "https://another.example.test"}} {
		foreign, err := db.KnownProjectServices(t.Context(), selection.project, selection.server)
		if err != nil || len(foreign) != 0 {
			t.Fatalf("locally known services crossed projects or servers: %v, %v", foreign, err)
		}
	}
	// older entries stay discoverable until they expire.
	var ticks atomic.Int64
	ticks.Store(time.Now().UnixNano())
	db.now = func() time.Time { return time.Unix(0, ticks.Add(1)) }
	for i := range 260 {
		options.ServiceID = fmt.Sprintf("svc_%022d", i)
		tunnel, err := db.BeginTunnel(t.Context(), options)
		if err != nil {
			t.Fatal(err)
		}
		if err := tunnel.Finish(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
	}
	ids, err = db.KnownProjectServices(t.Context(), project, server)
	if err != nil || len(ids) != 261 || ids[len(ids)-1] != first {
		t.Fatalf("incomplete project service inventory: %d, err=%v", len(ids), err)
	}
	if ids[0] != "svc_0000000000000000000259" {
		t.Fatalf("latest project service is %q", ids[0])
	}
	ticks.Add(int64(31 * 24 * time.Hour))
	options.ServiceID = first
	tunnel, err = db.BeginTunnel(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnel.Finish(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	ids, err = db.KnownProjectServices(t.Context(), project, server)
	if err != nil || len(ids) != 1 || ids[0] != first {
		t.Fatal("expired project inventory outlived its bounded retention", ids, err)
	}
}
