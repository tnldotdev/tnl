package state

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIntegrationBaselineACMEAuthorizationConstraints(t *testing.T) {
	f := newServicePublicationFixture(t)
	database, now := f.database, f.now
	pool := database.pool
	for _, query := range []string{
		`INSERT INTO control.acme_accounts (id, directory_url, contact_email, account_key_ciphertext, account_key_storage_key_id, created_at, updated_at)
		VALUES ('legacy-account', 'https://acme.example.test/directory', 'operator@example.test', decode(repeat('03',32),'hex'), 'legacy-key', $1, $1)`,
		`INSERT INTO control.acme_orders (id, account_id, service_run_id, service_id, service_run_number, idempotency_key, request_digest,
			certificate_cache_key, certificate_scope, certificate_domain_id, certificate_identifiers, challenge_method, csr_der, csr_digest, state, available_at, created_at, updated_at)
		SELECT 'legacy-order-' || n, 'legacy-account', run.id, run.service_id, run.run_number, 'order-' || n, decode(repeat('04',32),'hex'),
			run.certificate_cache_key, run.certificate_scope, run.certificate_domain_id, run.certificate_identifiers,
			'dns-01', decode('01','hex'), decode(repeat('0' || n,32),'hex'), 'authorizing', $1, $1, $1
		FROM control.service_runs run CROSS JOIN generate_series(1,2) AS n`,
		`INSERT INTO control.acme_authorizations (id, order_id, identifier, authorization_url, challenge_type, challenge_url, challenge_token,
			challenge_digest, presentation_reference, state, available_at, expires_at, created_at, updated_at)
		VALUES ('legacy-authorization', 'legacy-order-1', (SELECT certificate_hostname FROM control.service_runs LIMIT 1), 'https://acme.example.test/authz/shared',
			'dns-01', 'https://acme.example.test/challenge/legacy', 'legacy-token', decode(repeat('05',32),'hex'), 'fixture-presentation', 'presenting',
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
		VALUES ('reused', 'legacy-order-2', (SELECT certificate_hostname FROM control.service_runs LIMIT 1), 'https://acme.example.test/authz/shared',
		'complete', $1::timestamptz, $1::timestamptz, $1::timestamptz,
		$1::timestamptz + interval '1 hour', $1::timestamptz, $1::timestamptz)`, now); err != nil {
		t.Fatalf("reused authorization rejected: %v", err)
	}
	for _, test := range []struct{ name, query, code string }{
		{"partial_challenge", `UPDATE control.acme_authorizations SET challenge_token = NULL WHERE id = 'legacy-authorization'`, "23514"},
		{"dns_missing_presentation", `UPDATE control.acme_authorizations SET presentation_reference = NULL WHERE id = 'legacy-authorization'`, "23514"},
		{"unsupported_tls_alpn_without_presentation", `UPDATE control.acme_authorizations SET challenge_type = 'tls-alpn-01', presentation_reference = NULL WHERE id = 'legacy-authorization'`, "23514"},
		{"unsupported_tls_alpn_with_presentation", `UPDATE control.acme_authorizations SET challenge_type = 'tls-alpn-01' WHERE id = 'legacy-authorization'`, "23514"},
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
