package controlstate

import (
	"database/sql"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
)

func TestIntegrationControlStateMigrationUpgrade(t *testing.T) {
	databaseURL := newDisposableControlStateDatabaseURL(t, "authorization_upgrade")
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(t.Context(), "CREATE SCHEMA control"); err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, os.DirFS("migrations"),
		goose.WithTableName("control.goose_db_version"), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.UpTo(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	// Seed the actual v1 schema without passing the current-version Open gate.
	pool, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	now := time.Now().UTC().Truncate(time.Second)
	seedControlRoute(t, &Database{pool: pool}, now, "legacy")
	for _, query := range []string{
		`INSERT INTO control.route_sessions (id, route_id, team_id, acting_identity_id, route_version,
			idempotency_key, request_digest, session_token_id, session_token_digest, policy_revision,
			certificate_cache_key, certificate_scope, certificate_identifiers, certificate_challenge,
			state, created_at, last_heartbeat_at, publisher_expires_at)
		VALUES ('legacy-session', 'route_legacy', 'team_legacy', 'identity_legacy', 1, 'legacy',
			decode(repeat('01',32),'hex'), 'legacy-token', decode(repeat('02',32),'hex'), 1,
			'legacy-cache', 'route', ARRAY['route-legacy.example.test'], 'tls-alpn-01', 'starting',
			$1::timestamptz, $1::timestamptz, $1::timestamptz + interval '1 hour')`,
		`INSERT INTO control.acme_accounts (id, directory_url, contact_email, account_key_ciphertext, account_key_storage_key_id, created_at, updated_at)
		VALUES ('legacy-account', 'https://acme.example.test/directory', 'operator@example.test', decode(repeat('03',32),'hex'), 'legacy-key', $1, $1)`,
		`INSERT INTO control.acme_orders (id, account_id, route_session_id, route_id, route_version, idempotency_key, request_digest,
			certificate_cache_key, certificate_scope, certificate_identifiers, challenge_method, csr_der, csr_digest, state, available_at, created_at, updated_at)
		SELECT 'legacy-order-' || n, 'legacy-account', 'legacy-session', 'route_legacy', 1, 'order-' || n, decode(repeat('04',32),'hex'),
			'legacy-cache', 'route', ARRAY['route-legacy.example.test'], 'tls-alpn-01', decode('01','hex'), decode(repeat('0' || n,32),'hex'), 'authorizing', $1, $1, $1
		FROM generate_series(1,2) AS n`,
		`INSERT INTO control.acme_authorizations (id, order_id, identifier, authorization_url, challenge_type, challenge_url, challenge_token,
			challenge_digest, state, available_at, expires_at, created_at, updated_at)
		VALUES ('legacy-authorization', 'legacy-order-1', 'route-legacy.example.test', 'https://acme.example.test/authz/shared',
			'tls-alpn-01', 'https://acme.example.test/challenge/legacy', 'legacy-token', decode(repeat('05',32),'hex'), 'presenting',
			$1::timestamptz, $1::timestamptz + interval '1 hour', $1::timestamptz, $1::timestamptz)`,
	} {
		if _, err := pool.Exec(t.Context(), query, now); err != nil {
			t.Fatal(err)
		}
	}
	const snapshotQuery = `SELECT jsonb_build_object(
		'route', (SELECT to_jsonb(r) FROM control.routes r WHERE id = 'route_legacy'),
		'session', (SELECT to_jsonb(s) - 'assignments_open' FROM control.route_sessions s WHERE id = 'legacy-session'),
		'account', (SELECT to_jsonb(a) FROM control.acme_accounts a WHERE id = 'legacy-account'),
		'orders', (SELECT jsonb_agg(to_jsonb(o) ORDER BY id) FROM control.acme_orders o),
		'authorization', (SELECT to_jsonb(a) FROM control.acme_authorizations a WHERE id = 'legacy-authorization'))::text`
	var before string
	if err := pool.QueryRow(t.Context(), snapshotQuery).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if old, err := Open(t.Context(), databaseURL, testStorageKey, ""); err == nil {
		old.Close()
		t.Fatal("Open accepted v1 without migration")
	}
	for range 2 {
		if err := Migrate(t.Context(), databaseURL); err != nil {
			t.Fatal(err)
		}
	}
	database, err := Open(t.Context(), databaseURL, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	if err := database.Readiness(t.Context()); err != nil {
		t.Fatal(err)
	}
	var after string
	if err := pool.QueryRow(t.Context(), snapshotQuery).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatal("upgrade changed legacy route, session, account, order or authorization material")
	}
	// The reservation migration adds derived eligibility, not session material.
	var assignmentsOpen bool
	if err := pool.QueryRow(t.Context(), `SELECT assignments_open FROM control.route_sessions WHERE id = 'legacy-session'`).Scan(&assignmentsOpen); err != nil || !assignmentsOpen {
		t.Fatalf("upgraded open session eligibility=%t: %v", assignmentsOpen, err)
	}
	var version int64
	if err := pool.QueryRow(t.Context(), `SELECT max(version_id) FROM control.goose_db_version WHERE is_applied`).Scan(&version); err != nil || version != schemaVersion {
		t.Fatalf("upgraded schema version = %d, %v", version, err)
	}
	// A reused authorization has no challenge material and may share an ACME
	// authorization URL with an older order, but never within the same order.
	if _, err := pool.Exec(t.Context(), `INSERT INTO control.acme_authorizations (
		id, order_id, identifier, authorization_url, state, available_at, validated_at,
		cleanup_completed_at, expires_at, created_at, updated_at)
		VALUES ('reused', 'legacy-order-2', 'route-legacy.example.test', 'https://acme.example.test/authz/shared',
		'complete', $1::timestamptz, $1::timestamptz, $1::timestamptz,
		$1::timestamptz + interval '1 hour', $1::timestamptz, $1::timestamptz)`, now); err != nil {
		t.Fatalf("reused authorization rejected: %v", err)
	}
	for _, test := range []struct{ name, query, code string }{
		{"partial_challenge", `UPDATE control.acme_authorizations SET challenge_token = NULL WHERE id = 'legacy-authorization'`, "23514"},
		{"unfinished_reuse", `UPDATE control.acme_authorizations SET state = 'presenting' WHERE id = 'reused'`, "23514"},
		{"unvalidated_reuse", `UPDATE control.acme_authorizations SET validated_at = NULL WHERE id = 'reused'`, "23514"},
		{"uncleaned_reuse", `UPDATE control.acme_authorizations SET cleanup_completed_at = NULL WHERE id = 'reused'`, "23514"},
		{"presented_reuse", `UPDATE control.acme_authorizations SET presented_at = created_at WHERE id = 'reused'`, "23514"},
		{"attempted_reuse", `UPDATE control.acme_authorizations SET attempts = 1 WHERE id = 'reused'`, "23514"},
		{"expired_reuse", `UPDATE control.acme_authorizations SET validated_at = expires_at WHERE id = 'reused'`, "23514"},
		{"same_order_url", `INSERT INTO control.acme_authorizations (id, order_id, identifier, authorization_url, state, available_at, validated_at, cleanup_completed_at, expires_at, created_at, updated_at)
			SELECT 'duplicate', order_id, 'another.example.test', authorization_url, state, available_at, validated_at, cleanup_completed_at, expires_at, created_at, updated_at FROM control.acme_authorizations WHERE id = 'reused'`, "23505"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := pool.Exec(t.Context(), test.query)
			var postgresError *pgconn.PgError
			if !errors.As(err, &postgresError) || postgresError.Code != test.code {
				t.Fatalf("constraint error = %v, want SQLSTATE %s", err, test.code)
			}
		})
	}
}
