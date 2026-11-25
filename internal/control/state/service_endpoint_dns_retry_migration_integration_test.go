package state

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationServiceEndpointDNSRetryMigration(t *testing.T) {
	for _, prior := range []int64{1, 2, 3} {
		t.Run(fmt.Sprintf("from-v%d", prior), func(t *testing.T) {
			checkPopulatedDNSSchemaUpgrade(t, prior)
		})
	}
}

func checkPopulatedDNSSchemaUpgrade(t *testing.T, priorVersion int64) {
	t.Helper()
	ctx := t.Context()
	url := newDisposableControlStateDatabaseURL(t, "dns_retry_migration")
	cfg, err := parseDirectConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	sqlDB := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { _ = sqlDB.Close() })
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
	if _, err := provider.UpTo(ctx, priorVersion); err != nil {
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
	const aliasHost = "p-aaaaaaaaaaaaaaaaaaaaaaaaaa.live.example.test"
	if _, err := pool.Exec(ctx, `
	    INSERT INTO control.publisher_identities(id,team_id,name,kind,created_by_identity_id,ownership,created_at)
	        VALUES ('publisher','team','browser','run','actor','team',now());
	    INSERT INTO control.publisher_identity_keys(id,publisher_identity_id,public_key,revision,created_at)
	        VALUES ('signing-key','publisher',sha256('key'::bytea),1,now());
	    INSERT INTO control.publisher_grants(id,publisher_identity_id,team_id,created_by_identity_id,kind,service_id,protocols,created_at)
	        VALUES ('grant','publisher','team','actor','service','svc_0123456789ABCDEFGHIJKL',ARRAY['http'],now());
	    INSERT INTO control.service_runs
	        (id,service_id,team_id,protocol,run_number,publisher_identity_id,publisher_grant_id,publisher_key_id,
	         idempotency_key,request_digest,preparation_expires_at,assignment_seed_ciphertext,assignment_seed_storage_key_id,
	         state,traffic_limits,certificate_cache_key,certificate_scope,certificate_identifiers,certificate_domain_id,
	         certificate_hostname,certificate_namespace,run_hostname,run_alias_parent,created_at,publisher_expires_at,
	         serving_observed_at,serving_until)
	        VALUES ('srun_0123456789ABCDEFGHIJKL','svc_0123456789ABCDEFGHIJKL','team','http',1,'publisher','grant','signing-key',
	                'legacy',sha256('legacy'::bytea),now()+interval '1 minute','legacy-seed'::bytea,'legacy-key',
	                'prepared','{}','legacy-cache-key','app.example.test',ARRAY['app.example.test','p-aaaaaaaaaaaaaaaaaaaaaaaaaa.live.example.test'],
	                'domain','app.example.test','app.example.test','p-aaaaaaaaaaaaaaaaaaaaaaaaaa.live.example.test',
	                'live.example.test',now(),now()+interval '1 minute',now(),now()+interval '1 minute');
	    INSERT INTO control.service_endpoints
	        (hostname,service_id,service_run_id,publisher_identity_id,publisher_alias_parent,domain_id,namespace,
	         ingress_pool_id,public,dns_automation,dns_state,created_at)
	        VALUES ('p-aaaaaaaaaaaaaaaaaaaaaaaaaa.live.example.test','svc_0123456789ABCDEFGHIJKL',
	                'srun_0123456789ABCDEFGHIJKL','publisher','live.example.test','domain',
	                'p-aaaaaaaaaaaaaaaaaaaaaaaaaa.live.example.test','ingress-a',true,true,'published',now());`); err != nil {
		t.Fatal(err)
	}
	snapshot := func() string {
		t.Helper()
		var value string
		if err := pool.QueryRow(ctx, `SELECT jsonb_build_array(
		    (SELECT to_jsonb(s) FROM control.services s WHERE id=$1),
		    (SELECT jsonb_agg(to_jsonb(e)-'dns_consecutive_errors'-'wildcard_dns' ORDER BY hostname)
		     FROM control.service_endpoints e WHERE service_id=$1))::text`, serviceID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := snapshot()
	runtimeURL := rollingMigrationRuntimeURL(t, sqlDB, url, cfg.Database+"_read_runtime")
	// some installations grant writes to future tables by default. the runtime
	// needs the same read-only change records in both configurations.
	if priorVersion == 2 {
		if _, err := sqlDB.ExecContext(ctx, `ALTER DEFAULT PRIVILEGES IN SCHEMA control GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO `+pgx.Identifier{cfg.Database + "_read_runtime"}.Sanitize()); err != nil {
			t.Fatal(err)
		}
	}
	runtime, err := pgxpool.New(ctx, runtimeURL)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	oldRead := func(pool *pgxpool.Pool) {
		t.Helper()
		var name string
		if err := pool.QueryRow(ctx, `SELECT name FROM control.services WHERE id=$1`, serviceID).Scan(&name); err != nil || name != "app" {
			t.Fatal("old service read", name, err)
		}
	}
	oldRead(runtime)
	if version, err := readSchemaVersion(ctx, pool); err != nil || version != priorVersion {
		t.Fatal("fixture is not on the previous schema", version, err)
	}
	versionError := fmt.Sprintf("incompatible database schema version %d", priorVersion)
	if err := (&Database{pool: pool}).Readiness(ctx); err == nil || !strings.Contains(err.Error(), versionError) {
		t.Fatal("readiness accepted the unmigrated database", err)
	}
	prior, err := Open(ctx, url, testStorageKey, "", naming.ManagedURLModeGenerated)
	if prior != nil {
		prior.Close()
	}
	if err == nil || !strings.Contains(err.Error(), versionError) {
		t.Fatal("serving accepted the unmigrated database", err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE control.operator_nameserver_hostnames RENAME TO unsupported_nameserver_layout`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, url); err == nil || !strings.Contains(err.Error(), "incompatible version 1 database schema") {
		t.Fatal("migration accepted an older database marked v1", err)
	}
	if version, err := readSchemaVersion(ctx, pool); err != nil || version != priorVersion || snapshot() != before {
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
	oldRead(runtime)
	if _, err := runtime.Exec(ctx, `SELECT control.touch_visitor_policy_watch($1)`, serviceID); err != nil {
		t.Fatal("old write after migration", err)
	}
	var recorded bool
	if err := runtime.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.read_dependency_versions WHERE topic='watch' AND bucket=(hashtext($1)&255))`, serviceID).Scan(&recorded); err != nil || !recorded {
		t.Fatal("runtime could not read committed invalidation", err)
	}
	if _, err := runtime.Exec(ctx, `DELETE FROM control.read_dependency_versions WHERE false`); err == nil {
		t.Fatal("reader can erase change records")
	}
	reopened, err := Open(ctx, runtimeURL, testStorageKey, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.Readiness(ctx); err != nil {
		t.Fatal(err)
	}
	changes, err := reopened.CompareConnectorPeerWatchVersions(ctx, []ConnectorPeerWatchVersion{{RunID: "srun_0123456789ABCDEFGHIJKL"}})
	if err != nil || len(changes) != 1 || changes[0].Revision != -1 {
		t.Fatal("watch on prepared run after migration", changes, err)
	}
	if err := reopened.pool.QueryRow(ctx, `SELECT control.publisher_alias_dns_until(e,$2) IS NOT NULL
		FROM control.service_endpoints e WHERE e.hostname=$1`, aliasHost, now).Scan(&recorded); err != nil || !recorded {
		t.Fatal("older runtime cannot check alias DNS after migration", err)
	}
	var legacyExact bool
	if err := pool.QueryRow(ctx, `SELECT NOT wildcard_dns AND dns_automation AND dns_state='published'
	    FROM control.service_endpoints WHERE hostname=$1 AND publisher_identity_id='publisher'`, aliasHost).Scan(&legacyExact); err != nil || !legacyExact {
		t.Fatal("migration converted a legacy publisher hostname", err)
	}
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
