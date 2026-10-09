package controlstate

import (
	"context"
	"errors"
	"io/fs"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/storagekey"
)

func TestIntegrationPostgresMigrationAndOpen(t *testing.T) {
	databaseURL := newDisposableControlStateDatabaseURL(t, "migration")
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	const callers = 4
	results := make(chan error, callers)
	for range callers {
		workers.Go(func() { results <- Migrate(ctx, databaseURL) })
	}
	for range callers {
		if err := awaitIntegrationResult(t, ctx, results); err != nil {
			t.Fatalf("concurrent migration: %v", err)
		}
	}
	if err := Migrate(ctx, databaseURL); err != nil {
		t.Fatalf("repeat migration: %v", err)
	}
	database, err := Open(ctx, databaseURL, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	if err := database.Health(ctx); err != nil {
		t.Fatal(err)
	}
	if err := database.Readiness(ctx); err != nil {
		t.Fatal(err)
	}
	if mode := database.pool.Config().ConnConfig.DefaultQueryExecMode; mode != pgx.QueryExecModeExec {
		t.Fatalf("query mode = %v, want exec", mode)
	}
	for _, table := range []string{
		"identities", "oidc_assertion_exchanges", "managed_label_reservations", "teams", "member_slug_reservations", "team_memberships", "team_invitations", "domains", "control_sessions", "runtime_secret", "dns_authorities", "dns_challenge_changes",
		"public_urls", "publish_runs", "publish_run_connection_slots", "relay_services", "relay_leases", "ingress_leases", "ingress_routing_table_clock", "ingress_routing_table_events", "relay_service_assignment_totals",
		"control_tls_cache", "acme_accounts", "relay_certificate_orders", "acme_orders", "acme_authorizations", "ingress_usage_runs", "ingress_usage_reports",
		"public_url_usage_configuration", "public_url_usage_buckets", "public_url_usage_deliveries", "public_url_recovery_episodes", "public_url_recovery_histogram", "admin_audit_events", "maintenance_controls", "schema_migration_lock",
	} {
		var exists bool
		if err := database.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'control' AND table_name = $1)`, table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Errorf("control.%s missing after migration", table)
		}
		var key string
		if err := database.pool.QueryRow(ctx, `SELECT a.attname FROM pg_constraint AS c
			JOIN pg_attribute AS a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
			WHERE c.conrelid = ('control.' || $1)::regclass AND c.contype = 'p'`, table).Scan(&key); err != nil || key != "id" {
			t.Errorf("control.%s primary key = %q, %v; want id", table, key, err)
		}
	}
	var version int64
	if err := database.pool.QueryRow(ctx, `SELECT MAX(version_id) FILTER (WHERE is_applied) FROM control.goose_db_version`).Scan(&version); err != nil || version != schemaVersion {
		t.Fatalf("schema version = %d, %v", version, err)
	}
	// a newer additive migration must not make serving processes unready.
	if _, err := database.pool.Exec(ctx, `ALTER TABLE control.public_urls ADD COLUMN future_note text`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(ctx, `INSERT INTO control.goose_db_version (version_id, is_applied) VALUES ($1, true)`, schemaVersion+1); err != nil {
		t.Fatal(err)
	}
	if err := database.Readiness(ctx); err != nil {
		t.Fatalf("Readiness rejected additive newer schema: %v", err)
	}
	newer, err := Open(ctx, databaseURL, testStorageKey, "")
	if err != nil {
		t.Fatalf("Open rejected additive newer schema: %v", err)
	}
	newer.Close()
}

func TestIntegrationCustomDomainMigrationConvertsExistingRows(t *testing.T) {
	ctx := t.Context()
	url := newDisposableControlStateDatabaseURL(t, "custom_domain_migration")
	config, err := parseDirectConfig(url)
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
	if _, err := provider.UpTo(ctx, 13); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	now := time.Now().UTC()
	for _, statement := range []string{
		`INSERT INTO control.identities (id, kind, display_name, created_at, updated_at)
			VALUES ('identity_custom_upgrade', 'authority', 'Test', $1, $1)`,
		`INSERT INTO control.managed_label_reservations (label, created_at) VALUES ('team-custom-upgrade', $1)`,
		`INSERT INTO control.teams (id, kind, display_name, managed_label, created_by_identity_id, created_at, updated_at)
			VALUES ('team_custom_upgrade', 'personal', 'Test', 'team-custom-upgrade', 'identity_custom_upgrade', $1, $1)`,
		`INSERT INTO control.domains (id, kind, team_id, canonical_domain, state, authority_revision, created_by_identity_id, created_at, updated_at)
			VALUES ('domain_custom_upgrade', 'claimed', 'team_custom_upgrade', 'custom.example.test', 'ready', 1, 'identity_custom_upgrade', $1, $1)`,
	} {
		if _, err := pool.Exec(ctx, statement, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	var kind string
	if err := pool.QueryRow(ctx, `SELECT kind FROM control.domains WHERE id = 'domain_custom_upgrade'`).Scan(&kind); err != nil || kind != "custom" {
		t.Fatalf("migrated domain kind = %q, %v", kind, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE control.domains SET kind = 'claimed' WHERE id = 'domain_custom_upgrade'`); err == nil {
		t.Fatal("legacy domain kind was still writable")
	}
}

func TestIntegrationBrowserAccessAndFeedbackPolicyMigration(t *testing.T) {
	ctx := t.Context()
	url := newDisposableControlStateDatabaseURL(t, "browser_policy_migration")
	config, err := parseDirectConfig(url)
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
	if _, err := provider.UpTo(ctx, 17); err != nil {
		t.Fatal(err)
	}
	if old, err := Open(ctx, url, testStorageKey, ""); err == nil {
		old.Close()
		t.Fatal("runtime accepted schema 17 before its generated columns were available")
	}
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	keyring, err := storagekey.New(testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	legacy := &Database{pool: pool, storageKey: keyring}
	now := time.Now().UTC().Truncate(time.Second)
	seedControlPublicURL(t, legacy, now, "browser_upgrade")
	insertTestPublishRun(t, legacy, testPublishRun{
		ID: "run_browser_upgrade", PublicURLID: "public_url_browser_upgrade", TeamID: "team_browser_upgrade", ActingIdentityID: "identity_browser_upgrade",
		CertificateCacheKey: "browser-upgrade", CertificateScope: "public-url", CertificateIdentifiers: []string{"route-browser-upgrade.example.test"},
		ChallengeMethod: "tls-alpn-01", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	for _, statement := range []string{
		`INSERT INTO control.previews (id, team_id, created_by_identity_id, idempotency_key, created_at)
		 VALUES ('preview_browser_upgrade', 'team_browser_upgrade', 'identity_browser_upgrade', 'upgrade', $1)`,
		`INSERT INTO control.browser_login_attempts
		 (state_digest, binding_digest, preview_id, public_url_id, return_path, nonce, verifier_ciphertext, verifier_storage_key_id, expires_at)
		 VALUES (decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), 'preview_browser_upgrade',
		 'public_url_browser_upgrade', '/', 'upgrade-nonce', decode('03', 'hex'), 'test', $1::timestamptz + interval '1 hour')`,
		`INSERT INTO control.browser_access_sessions
		 (token_digest, preview_id, public_url_id, identity_id, display_name, access_ciphertext, refresh_ciphertext, storage_key_id, access_expires_at, expires_at)
		 VALUES (decode(repeat('04', 32), 'hex'), 'preview_browser_upgrade', 'public_url_browser_upgrade', 'identity_browser_upgrade',
		 'upgrade name', decode('05', 'hex'), decode('06', 'hex'), 'test', $1::timestamptz + interval '1 hour', $1::timestamptz + interval '1 day')`,
	} {
		if _, err := pool.Exec(ctx, statement, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	database, err := Open(ctx, url, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	queries := controlstatedb.New(database.pool)
	run, err := queries.GetPublishRun(ctx, "run_browser_upgrade")
	if err != nil || run.BrowserCapable {
		t.Fatalf("existing run's browser capability = %t, %v", run.BrowserCapable, err)
	}
	var requireSignIn bool
	if err := database.pool.QueryRow(ctx, `SELECT feedback_require_sign_in FROM control.teams WHERE id = 'team_browser_upgrade'`).Scan(&requireSignIn); err != nil || requireSignIn {
		t.Fatalf("existing team's sign-in policy = %t, %v", requireSignIn, err)
	}
	for _, table := range []string{"browser_login_attempts", "browser_access_sessions"} {
		var previewID string
		if err := database.pool.QueryRow(ctx, "SELECT preview_id FROM control."+table).Scan(&previewID); err != nil || previewID != "preview_browser_upgrade" {
			t.Fatalf("%s preview after upgrade = %q, %v", table, previewID, err)
		}
		if _, err := database.pool.Exec(ctx, "UPDATE control."+table+" SET preview_id = NULL"); err != nil {
			t.Fatalf("%s rejected a nullable preview reference: %v", table, err)
		}
	}
}

func TestIntegrationScopedForeignKeys(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "scoped_foreign_keys")
	seedControlPublicURL(t, database, now, "owner_a")
	seedControlPublicURL(t, database, now, "owner_b")
	insertTestPublishRun(t, database, testPublishRun{
		ID: "session_owner_a", PublicURLID: "public_url_owner_a", TeamID: "team_owner_a",
		ActingIdentityID: "identity_owner_a", CertificateCacheKey: "owner_a", CertificateScope: "owner_a",
		CertificateIdentifiers: []string{"route-owner_a.example.test"}, ChallengeMethod: "tls-alpn-01",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.member_slug_reservations
		(id, team_id, member_slug, state, created_at) VALUES
		('reservation_owner_b_extra', 'team_owner_b', 'extra', 'invited', $1)`, now); err != nil {
		t.Fatal(err)
	}
	account, err := database.EnsureACMEAccount(t.Context(), "https://acme.example.test/scoped-fk", "operator@example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, query string
		args        []any
	}{
		{name: "membership_slug", query: `UPDATE control.team_memberships SET slug_reservation_id = 'reservation_owner_b_extra' WHERE team_id = 'team_owner_a'`},
		{name: "invitation_slug", query: `INSERT INTO control.team_invitations (id, team_id, slug_reservation_id, initial_role,
			invited_by_identity_id, idempotency_key, request_digest, token_digest, state, created_at, expires_at)
			VALUES ('invitation_wrong_team', 'team_owner_a', 'reservation_owner_b_extra', 'member', 'identity_owner_a',
			'wrong-team', decode(repeat('01', 32), 'hex'), decode(repeat('02', 32), 'hex'), 'pending', now(), now() + interval '1 hour')`},
		{name: "publish_run_team", query: `UPDATE control.publish_runs SET team_id = 'team_owner_b' WHERE id = 'session_owner_a'`},
		{name: "missing_recovery_run", query: `INSERT INTO control.public_url_recovery_episodes (public_url_id, publish_run_number, state, opened_at) VALUES ('public_url_owner_a', 2, 'open', now())`},
		{name: "acme_order_run", query: `INSERT INTO control.acme_orders (id, account_id, publish_run_id, public_url_id, publish_run_number,
			idempotency_key, request_digest, certificate_cache_key, certificate_scope, certificate_identifiers,
			challenge_method, csr_der, csr_digest, state, available_at, created_at, updated_at)
			VALUES ('order_wrong_run', $1, 'session_owner_a', 'public_url_owner_b', 1,
			'wrong-run', decode(repeat('03', 32), 'hex'), 'owner_a', 'owner_a', ARRAY['owner-a.example.test'],
			'tls-alpn-01', decode('01', 'hex'), decode(repeat('04', 32), 'hex'), 'pending', now(), now(), now())`, args: []any{account.ID}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := database.pool.Exec(t.Context(), test.query, test.args...)
			var constraint *pgconn.PgError
			if !errors.As(err, &constraint) || constraint.Code != "23503" {
				t.Fatalf("foreign key error = %v; want 23503", err)
			}
		})
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.teams SET default_domain_id = 'domain_owner_b' WHERE id = 'team_owner_a'`); err == nil {
		t.Fatal("another team's custom domain became the default")
	}
}

func TestIntegrationPublisherConnectionSchemaConstraints(t *testing.T) {
	f := newPublishRunFixture(t)
	// exercise the constraints on real rows, rather than matching SQL source
	// spelling. each failing statement is atomic and leaves the fixture intact.
	for _, test := range []struct{ name, query, code string }{
		{"slot_lower_bound", `UPDATE control.publish_run_connection_slots SET connection_slot = -1 WHERE connection_slot = 0`, "23514"},
		{"slot_upper_bound", `UPDATE control.publish_run_connection_slots SET connection_slot = 2 WHERE connection_slot = 1`, "23514"},
		{"distinct_services", `UPDATE control.publish_run_connection_slots SET relay_service_id = (SELECT relay_service_id FROM control.publish_run_connection_slots WHERE connection_slot = 0) WHERE connection_slot = 1`, "23505"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := f.database.pool.Exec(t.Context(), test.query)
			var postgresError *pgconn.PgError
			if !errors.As(err, &postgresError) || postgresError.Code != test.code {
				t.Fatalf("constraint error = %v, want SQLSTATE %s", err, test.code)
			}
		})
	}
}
