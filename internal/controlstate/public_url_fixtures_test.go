package controlstate

import (
	"testing"
	"time"
)

// seedControlPublicURL supplies local authority and an enabled shared route. It
// deliberately does not create relay leases, route sessions, or ACME work.
func seedControlPublicURL(t *testing.T, database *Database, now time.Time, suffix string) {
	t.Helper()
	identityID, teamID := "identity_"+suffix, "team_"+suffix
	reservationID, membershipID := "reservation_"+suffix, "membership_"+suffix
	domainID, publicURLID := "domain_"+suffix, "public_url_"+suffix
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO control.identities (id, kind, display_name, administrator, created_at, updated_at)
			VALUES ($2, 'authority', 'Test identity', true, $1, $1)`, []any{now, identityID}},
		{`INSERT INTO control.managed_label_reservations (label, created_at) VALUES ($2, $1), ($3, $1)`, []any{now, "team-" + suffix, "member-" + suffix}},
		{`INSERT INTO control.teams (id, kind, display_name, managed_label, created_by_identity_id, created_at, updated_at)
			VALUES ($2, 'personal', 'Team', $3, $4, $1, $1)`, []any{now, teamID, "team-" + suffix, identityID}},
		{`INSERT INTO control.member_slug_reservations (id, team_id, member_slug, state, reserved_by_identity_id, created_at, activated_at)
			VALUES ($2, $3, $4, 'active', $5, $1, $1)`, []any{now, reservationID, teamID, "member-" + suffix, identityID}},
		{`INSERT INTO control.team_memberships (id, team_id, identity_id, slug_reservation_id, managed_label, role, authority_revision, created_at, updated_at)
			VALUES ($2, $3, $4, $5, $6, 'owner', 1, $1, $1)`, []any{now, membershipID, teamID, identityID, reservationID, "member-" + suffix}},
		{`INSERT INTO control.domains (id, kind, team_id, canonical_domain, state, authority_revision, created_by_identity_id, created_at, verified_at, updated_at)
			VALUES ($2, 'claimed', $3, $4, 'ready', 1, $5, $1, $1, $1)`, []any{now, domainID, teamID, suffix + ".example.test", identityID}},
		{`UPDATE control.teams SET default_domain_id = $1 WHERE id = $2`, []any{domainID, teamID}},
		{`INSERT INTO control.public_urls (id, team_id, domain_id, created_by_identity_id, idempotency_key, request_digest, canonical_hostname,
			target, public_url_scope, policy_revision, ip_policy, lifecycle_state, dns_state, created_at, updated_at)
			VALUES ($2, $3, $4, $5, 'seed', decode(repeat('00', 32), 'hex'), $6,
			'http://127.0.0.1:3000', 'shared', 1, 'allow_all', 'enabled', 'published', $1, $1)`, []any{now, publicURLID, teamID, domainID, identityID, "route-" + suffix + ".example.test"}},
	} {
		if _, err := database.pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}
