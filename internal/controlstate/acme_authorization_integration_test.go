package controlstate

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestIntegrationBaselineACMEAuthorizationConstraints(t *testing.T) {
	databaseURL := newDisposableControlStateDatabaseURL(t, "authorization_baseline")
	if err := Migrate(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	now := time.Now().UTC().Truncate(time.Second)
	seedControlPublicURL(t, &Database{pool: pool}, now, "legacy")
	insertTestPublishRun(t, &Database{pool: pool}, testPublishRun{
		ID: "legacy-session", PublicURLID: "public_url_legacy", TeamID: "team_legacy", ActingIdentityID: "identity_legacy",
		CertificateCacheKey: "legacy-cache", CertificateScope: "route",
		CertificateIdentifiers: []string{"route-legacy.example.test"}, ChallengeMethod: "tls-alpn-01",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	})
	for _, query := range []string{
		`INSERT INTO control.acme_accounts (id, directory_url, contact_email, account_key_ciphertext, account_key_storage_key_id, created_at, updated_at)
		VALUES ('legacy-account', 'https://acme.example.test/directory', 'operator@example.test', decode(repeat('03',32),'hex'), 'legacy-key', $1, $1)`,
		`INSERT INTO control.acme_orders (id, account_id, publish_run_id, public_url_id, publish_run_number, idempotency_key, request_digest,
			certificate_cache_key, certificate_scope, certificate_identifiers, challenge_method, csr_der, csr_digest, state, available_at, created_at, updated_at)
		SELECT 'legacy-order-' || n, 'legacy-account', 'legacy-session', 'public_url_legacy', 1, 'order-' || n, decode(repeat('04',32),'hex'),
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
	// a reused authorization has no challenge material and may share an ACME
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
