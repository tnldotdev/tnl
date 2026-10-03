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
	database := &Database{pool: pool}
	now := time.Now().UTC().Truncate(time.Second)
	seedControlPublicURL(t, database, now, "usage_reset")
	insertTestPublishRun(t, database, testPublishRun{
		ID: "publish_run_usage_reset", PublicURLID: "public_url_usage_reset", TeamID: "team_usage_reset",
		ActingIdentityID: "identity_usage_reset", CertificateCacheKey: "usage-reset", CertificateScope: "usage-reset",
		CertificateIdentifiers: []string{"route-usage_reset.example.test"}, ChallengeMethod: "tls-alpn-01",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	})
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
	if err := Migrate(ctx, databaseURL); err != nil {
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
		t.Fatalf("migration removed saved public URL: %d, %v", count, err)
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
