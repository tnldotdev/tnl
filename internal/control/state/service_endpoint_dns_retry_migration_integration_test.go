package state

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationServiceEndpointDNSRetryMigration(t *testing.T) {
	ctx := t.Context()
	url := newDisposableControlStateDatabaseURL(t, "dns_retry_migration")
	cfg, err := parseDirectConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB := stdlib.OpenDB(*cfg)
	defer sqlDB.Close()
	if err := ensureMigrationLock(ctx, sqlDB); err != nil {
		t.Fatal(err)
	}
	migrations, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, migrations,
		goose.WithTableName(versionTable), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(ctx, 1); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	const serviceID = "svc_0123456789ABCDEFGHIJKL"
	const retiredHost = "retired.example.test"
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := pool.Exec(ctx, `
	    INSERT INTO control.identities(id,kind,display_name,created_at,updated_at)
	        VALUES ('actor','authority','Actor',now(),now());
	    INSERT INTO control.managed_label_reservations(label,created_at) VALUES ('team',now());
	    INSERT INTO control.teams(id,kind,display_name,managed_label,created_by_identity_id,created_at,updated_at)
	        VALUES ('team','organization','team','team','actor',now(),now());
	    INSERT INTO control.domains(id,kind,canonical_domain,state,authority_revision,created_at,updated_at)
	        VALUES ('domain','managed','example.test','ready',1,now(),now());
	    INSERT INTO control.services(id,team_id,name,protocol,domain_id,certificate_hostname,created_by_identity_id,
	                                 idempotency_key,request_digest,created_at,updated_at)
	        VALUES ('svc_0123456789ABCDEFGHIJKL','team','app','http','domain','app.example.test','actor',
	                'create-app',sha256('create-app'::bytea),now(),now());`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO control.service_endpoints
	    (hostname,service_id,domain_id,namespace,ingress_pool_id,public,dns_automation,dns_state,
	     dns_revision,dns_attempts,dns_available_at,dns_last_error,dns_work_owner,dns_work_epoch,dns_work_expires_at,
	     created_at,retired_at,reusable_after)
	    VALUES ('app.example.test',$1,'domain','app.example.test','ingress-a',true,true,'published',
	            12,90,NULL,NULL,NULL,90,NULL,$2,NULL,NULL),
	           ($3,$1,'domain',$3,'ingress-a',false,true,'removing',
	            23,99,$2,'server.dns_failed','old-worker',99,$4,$2,$2,$5)`,
		serviceID, now, retiredHost, now.Add(time.Minute), now.Add(7*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	snapshot := func() string {
		t.Helper()
		var value string
		if err := pool.QueryRow(ctx, `SELECT jsonb_build_array(
		    (SELECT to_jsonb(s) FROM control.services s WHERE id=$1),
		    (SELECT jsonb_agg(to_jsonb(e)-'dns_consecutive_errors' ORDER BY hostname)
		     FROM control.service_endpoints e WHERE service_id=$1))::text`, serviceID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := snapshot()
	if version, err := readSchemaVersion(ctx, pool); err != nil || version != 1 {
		t.Fatal("fixture is not on the released v1 schema", version, err)
	}
	prior, err := Open(ctx, url, testStorageKey, "", naming.ManagedURLModeGenerated)
	if prior != nil {
		prior.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "incompatible database schema version 1") {
		t.Fatal("serving accepted the unmigrated database", err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE control.operator_nameserver_hostnames RENAME TO unsupported_nameserver_layout`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, url); err == nil || !strings.Contains(err.Error(), "incompatible version 1 database schema") {
		t.Fatal("migration accepted an older database marked v1", err)
	}
	if version, err := readSchemaVersion(ctx, pool); err != nil || version != 1 || snapshot() != before {
		t.Fatal("rejection changed migration history or saved state", version, err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE control.unsupported_nameserver_layout RENAME TO operator_nameserver_hostnames`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := Migrate(ctx, url); err != nil {
			t.Fatal(err)
		}
		if snapshot() != before {
			t.Fatal("migration changed the service, endpoint, or saved DNS work")
		}
	}
	d, err := Open(ctx, url, testStorageKey, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, found, err := d.ClaimServiceEndpointDNSWork(ctx, "next-worker", now, time.Minute); found || err != nil {
		t.Fatal("upgrade discarded the current work lease", found, err)
	}
	now = now.Add(time.Minute)
	work, found, err := d.ClaimServiceEndpointDNSWork(ctx, "next-worker", now, time.Minute)
	if err != nil || !found || work.Hostname != retiredHost || work.State != ServiceEndpointDNSRemoving ||
		work.ConsecutiveErrors != 0 || work.Attempts != 100 || work.Epoch != 100 || work.Revision != 23 || work.LastError != "server.dns_failed" {
		t.Fatal("upgrade did not preserve work or fabricated an error streak", found, work, err)
	}
	stale := work
	stale.Worker, stale.Epoch = "old-worker", 99
	if _, err := d.SaveServiceEndpointDNSWork(ctx, stale, now); !errors.Is(err, ErrServiceEndpointDNSWorkStale) {
		t.Fatal("pre-upgrade owner wrote after reassignment", err)
	}
	work.AvailableAt = now.Add(time.Second)
	if saved, err := d.SaveServiceEndpointDNSWork(ctx, work, now); err != nil || saved.ConsecutiveErrors != 1 {
		t.Fatal("first post-upgrade failure did not start a new streak", saved, err)
	}
	now = now.Add(time.Second)
	work, found, err = d.ClaimServiceEndpointDNSWork(ctx, "cleanup", now, time.Minute)
	if err != nil || !found || work.ConsecutiveErrors != 1 {
		t.Fatal("removal lost its new streak", found, work, err)
	}
	work.State, work.LastError, work.AvailableAt = ServiceEndpointDNSRemoved, "", time.Time{}
	if saved, err := d.SaveServiceEndpointDNSWork(ctx, work, now); err != nil || saved.ConsecutiveErrors != 0 {
		t.Fatal("successful removal did not reset the streak", saved, err)
	}
}
