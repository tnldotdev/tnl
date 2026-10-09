package controlstate

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"
)

// testPublishRun describes the identity and certificate plan of a saved run.
// tests that need to exercise the run insert itself should use direct SQL.
type testPublishRun struct {
	ID, PublicURLID, TeamID, MembershipID, ActingIdentityID string
	CertificateCacheKey, CertificateScope, ChallengeMethod  string
	CertificateIdentifiers                                  []string
	PolicyRevision                                          int64
	CreatedAt, ExpiresAt                                    time.Time
}

func insertTestPublishRun(t *testing.T, database *Database, run testPublishRun) {
	t.Helper()
	if run.PolicyRevision == 0 {
		run.PolicyRevision = 1
	}
	requestDigest := sha256.Sum256([]byte(run.ID))
	sealedDigest, err := database.sealSecret(publishRunRequestDigestContext(run.ID), requestDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	tokenDigest := sha256.Sum256([]byte("token:" + run.ID))
	if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.publish_runs (
		id, public_url_id, team_id, membership_id, acting_identity_id, publish_run_number,
		idempotency_key, request_digest_ciphertext, request_digest_storage_key_id, publish_run_token_id, publish_run_token_digest,
		policy_revision, certificate_cache_key, certificate_scope, certificate_identifiers,
		certificate_challenge_method, state, created_at, last_heartbeat_at, publisher_expires_at
		) VALUES ($1, $2, $3, $4, $5, 1, $1, $6, $7, $8, $9, $10, $11, $12, $13, $14,
		'starting', $15, $15, $16)`, run.ID, run.PublicURLID, run.TeamID, nullableTestMembership(run.MembershipID),
		run.ActingIdentityID, sealedDigest, database.storageKey.CurrentID(), "token_"+run.ID, tokenDigest[:], run.PolicyRevision,
		run.CertificateCacheKey, run.CertificateScope, run.CertificateIdentifiers, run.ChallengeMethod,
		run.CreatedAt, run.ExpiresAt); err != nil {
		t.Fatal(err)
	}
}

func nullableTestMembership(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// seedControlPublicURL supplies local authority and an enabled shared public
// URL. it does not create relay leases, publish runs, or ACME work.
func seedControlPublicURL(t *testing.T, database *Database, now time.Time, suffix string) {
	t.Helper()
	identityID, teamID := "identity_"+suffix, "team_"+suffix
	reservationID, membershipID := "reservation_"+suffix, "membership_"+suffix
	domainID, publicURLID := "domain_"+suffix, "public_url_"+suffix
	sealedDigest, err := database.sealSecret(publicURLRequestDigestContext(publicURLID), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	label := strings.ReplaceAll(suffix, "_", "-")
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO control.identities (id, kind, display_name, administrator, created_at, updated_at)
			VALUES ($2, 'authority', 'Test identity', true, $1, $1)`, []any{now, identityID}},
		{`INSERT INTO control.managed_label_reservations (label, created_at) VALUES ($2, $1), ($3, $1)`, []any{now, "team-" + label, "member-" + label}},
		{`INSERT INTO control.teams (id, kind, display_name, managed_label, created_by_identity_id, created_at, updated_at)
			VALUES ($2, 'personal', 'Team', $3, $4, $1, $1)`, []any{now, teamID, "team-" + label, identityID}},
		{`INSERT INTO control.member_slug_reservations (id, team_id, member_slug, state, reserved_by_identity_id, created_at, activated_at)
			VALUES ($2, $3, $4, 'active', $5, $1, $1)`, []any{now, reservationID, teamID, "member-" + label, identityID}},
		{`INSERT INTO control.team_memberships (id, team_id, identity_id, slug_reservation_id, managed_label, role, authority_revision, created_at, updated_at)
			VALUES ($2, $3, $4, $5, $6, 'owner', 1, $1, $1)`, []any{now, membershipID, teamID, identityID, reservationID, "member-" + label}},
		{`INSERT INTO control.domains (id, kind, team_id, canonical_domain, state, authority_revision, created_by_identity_id, created_at, verified_at, updated_at)
			VALUES ($2, 'custom', $3, $4, 'ready', 1, $5, $1, $1, $1)`, []any{now, domainID, teamID, suffix + ".example.test", identityID}},
		{`UPDATE control.teams SET default_domain_id = $1 WHERE id = $2`, []any{domainID, teamID}},
		{`INSERT INTO control.public_urls (id, team_id, domain_id, created_by_identity_id, idempotency_key,
			request_digest_ciphertext, request_digest_storage_key_id, canonical_hostname,
			target, public_url_scope, policy_revision, ip_policy, lifecycle_state, dns_state, created_at, updated_at)
			VALUES ($2, $3, $4, $5, 'seed', $6, $7, $8,
			'http://127.0.0.1:3000', 'shared', 1, 'allow_all', 'enabled', 'published', $1, $1)`,
			[]any{now, publicURLID, teamID, domainID, identityID, sealedDigest, database.storageKey.CurrentID(), "route-" + suffix + ".example.test"}},
		{`INSERT INTO control.public_url_purposes (public_url_id, purpose) VALUES ($1, 'app')`, []any{publicURLID}},
	} {
		if _, err := database.pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}
