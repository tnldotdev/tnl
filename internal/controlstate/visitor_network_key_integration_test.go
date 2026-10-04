package controlstate

import (
	"io/fs"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func TestIntegrationVisitorNetworkHashKeyEncryptedAndShared(t *testing.T) {
	database, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "visitor_network_key")
	first, err := database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "ingress_key_first", IngressRunID: "run_first", ProtocolVersion: 1, ConnectionCapacity: 10,
	}, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var ciphertext []byte
	var keyID string
	if err := database.pool.QueryRow(t.Context(), `SELECT visitor_network_hash_master_key_ciphertext,
		visitor_network_hash_master_key_storage_key_id FROM control.public_url_usage_configuration`).Scan(&ciphertext, &keyID); err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) <= 32 || keyID != database.storageKey.CurrentID() {
		t.Fatal("visitor network hash key was not stored only as a protected secret")
	}
	other, err := Open(t.Context(), databaseURL, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Close)
	second, err := other.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "ingress_key_second", IngressRunID: "run_second", ProtocolVersion: 1, ConnectionCapacity: 10,
	}, now, time.Minute)
	if err != nil || first.VisitorNetworkHashKeys != second.VisitorNetworkHashKeys {
		t.Fatalf("visitor network keys changed between control processes: %v", err)
	}
}

func TestIntegrationVisitorNetworkHashKeyMigrationDropsOldUsage(t *testing.T) {
	ctx := t.Context()
	databaseURL := newDisposableControlStateDatabaseURL(t, "visitor_network_key_migration")
	config, err := parseDirectConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	direct := stdlib.OpenDB(*config)
	t.Cleanup(func() { _ = direct.Close() })
	if err := ensureMigrationLock(ctx, direct); err != nil {
		t.Fatal(err)
	}
	migrations, err := fs.Sub(migrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, direct, migrations,
		goose.WithTableName(versionTable), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(ctx, 2); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	now := time.Now().UTC().Truncate(time.Second)
	seedLegacyUsagePublicURL(t, pool, now)
	legacyKey := [32]byte{1}
	if _, err := pool.Exec(ctx, `INSERT INTO control.public_url_usage_configuration
		(visitor_network_hash_master_key, created_at) VALUES ($1, $2)`, legacyKey[:], now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO control.ingress_usage_runs
		(ingress_id, ingress_run_id, ingress_lease_revision, started_at, lease_expires_at, observed_through)
		VALUES ('ingress_old', 'run_old', 1, $1, $2, $1)`, now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO control.ingress_usage_reports
		(ingress_id, ingress_run_id, public_url_id, publish_run_number, bucket_start, bucket_end,
		observed_through, report_revision, connection_attempts, policy_denials, capacity_denials,
		visitor_stream_open_failures, successful_streams, connection_nanoseconds, ingress_bytes,
		egress_bytes, histogram_data, received_at)
		VALUES ('ingress_old', 'run_old', 'public_url_usage_reset', 1, $1, $2,
		$1, 1, 1, 0, 0, 0, 0, 0, 0, 0, $3, $1)`, now, now.Add(time.Minute), []byte{1}); err != nil {
		t.Fatal(err)
	}
	var bucketID int64
	if err := pool.QueryRow(ctx, `INSERT INTO control.public_url_usage_buckets
		(public_url_id, publish_run_number, team_id, acting_identity_id, bucket_start, bucket_end,
		observed_through, histogram_data, updated_at)
		VALUES ('public_url_usage_reset', 1, 'team_usage_reset', 'identity_usage_reset', $1, $2, $1, $3, $1)
		RETURNING id`, now, now.Add(time.Minute), []byte{1}).Scan(&bucketID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO control.public_url_usage_deliveries
		(bucket_id, bucket_revision, delivery_key, state, available_at, created_at)
		VALUES ($1, 1, 'old-usage-delivery', 'pending', $2, $2)`, bucketID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(ctx, 3); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{
		"public_url_usage_configuration", "ingress_usage_runs", "ingress_usage_reports",
		"public_url_usage_buckets", "public_url_usage_deliveries",
	} {
		var count int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM control."+table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s retained %d old rows: %v", table, count, err)
		}
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM control.public_urls WHERE id = 'public_url_usage_reset'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("visitor-network migration removed saved public URL: %d, %v", count, err)
	}
	if err := Migrate(ctx, databaseURL); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM control.public_urls WHERE id = 'public_url_usage_reset'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("prelaunch IP-policy migration retained old public URL: %d, %v", count, err)
	}
	current, err := Open(ctx, databaseURL, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(current.Close)
	if _, err := current.RegisterIngress(ctx, IngressRegistration{
		IngressID: "ingress_new", IngressRunID: "run_new", ProtocolVersion: 1, ConnectionCapacity: 10,
	}, now, time.Minute); err != nil {
		t.Fatalf("register ingress after discarding old usage: %v", err)
	}
}

func seedLegacyUsagePublicURL(t *testing.T, pool *pgxpool.Pool, now time.Time) {
	t.Helper()
	for _, statement := range []string{
		`INSERT INTO control.identities (id, kind, display_name, administrator, created_at, updated_at)
			VALUES ('identity_usage_reset', 'authority', 'Test identity', true, $1, $1)`,
		`INSERT INTO control.managed_label_reservations (label, created_at)
			VALUES ('team-usage-reset', $1), ('member-usage-reset', $1)`,
		`INSERT INTO control.teams (id, kind, display_name, managed_label, created_by_identity_id, created_at, updated_at)
			VALUES ('team_usage_reset', 'personal', 'Team', 'team-usage-reset', 'identity_usage_reset', $1, $1)`,
		`INSERT INTO control.member_slug_reservations (id, team_id, member_slug, state, reserved_by_identity_id, created_at, activated_at)
			VALUES ('reservation_usage_reset', 'team_usage_reset', 'member-usage-reset', 'active', 'identity_usage_reset', $1, $1)`,
		`INSERT INTO control.team_memberships (id, team_id, identity_id, slug_reservation_id, managed_label, role, authority_revision, created_at, updated_at)
			VALUES ('membership_usage_reset', 'team_usage_reset', 'identity_usage_reset', 'reservation_usage_reset', 'member-usage-reset', 'owner', 1, $1, $1)`,
		`INSERT INTO control.domains (id, kind, team_id, canonical_domain, state, authority_revision, created_by_identity_id, created_at, verified_at, updated_at)
			VALUES ('domain_usage_reset', 'claimed', 'team_usage_reset', 'usage_reset.example.test', 'ready', 1, 'identity_usage_reset', $1, $1, $1)`,
		`INSERT INTO control.public_urls (id, team_id, domain_id, created_by_identity_id, idempotency_key,
			request_digest, canonical_hostname, target, public_url_scope, policy_revision, ip_policy, lifecycle_state,
			dns_state, created_at, updated_at)
			VALUES ('public_url_usage_reset', 'team_usage_reset', 'domain_usage_reset', 'identity_usage_reset', 'seed',
			decode(repeat('00', 32), 'hex'), 'route-usage_reset.example.test', 'http://127.0.0.1:3000', 'shared', 1,
			'allow_all', 'enabled', 'published', $1, $1)`,
	} {
		if _, err := pool.Exec(t.Context(), statement, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO control.publish_runs
		(id, public_url_id, team_id, acting_identity_id, publish_run_number, idempotency_key, request_digest,
		publish_run_token_id, publish_run_token_digest, policy_revision, certificate_cache_key, certificate_scope,
		certificate_identifiers, certificate_challenge_method, state, created_at, last_heartbeat_at, publisher_expires_at)
		VALUES ('publish_run_usage_reset', 'public_url_usage_reset', 'team_usage_reset', 'identity_usage_reset', 1,
		'publish_run_usage_reset', decode(repeat('00', 32), 'hex'), 'token_publish_run_usage_reset',
		decode(repeat('00', 32), 'hex'), 1, 'usage-reset', 'usage-reset', ARRAY['route-usage_reset.example.test'],
		'tls-alpn-01', 'starting', $1, $1, $2)`, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}
