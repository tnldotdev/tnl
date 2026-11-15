package state

import (
	"strings"
	"testing"
	"time"
)

type serviceTestAuthority struct {
	TeamID, MembershipID, ActingIdentityID, DomainID, CanonicalHostname string
}

// seedControlServiceAuthority supplies identity, membership, and domain facts.
// individual fixtures create their service and enrolled publisher explicitly.
func seedControlServiceAuthority(t *testing.T, database *Database, now time.Time, suffix string) serviceTestAuthority {
	t.Helper()
	identityID, teamID := "identity_"+suffix, "team_"+suffix
	reservationID, membershipID := "reservation_"+suffix, "membership_"+suffix
	domainID := "domain_" + suffix
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
	} {
		if _, err := database.pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return serviceTestAuthority{TeamID: teamID, MembershipID: membershipID, ActingIdentityID: identityID, DomainID: domainID,
		CanonicalHostname: "web.member-" + label + "." + suffix + ".example.test"}
}
