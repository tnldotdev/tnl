package state

import (
	"errors"
	"testing"
)

func TestIntegrationCompanyAdmissionOwnerRetryRechecksEligibility(t *testing.T) {
	d, now, owner, team := newAuthorityTeam(t)
	p := companyTestPrincipal(t, d, newOIDCSession(t, d, now), now)
	c := companyTestConnection(t, d, team.ID, p, "approval", now)
	var ownerMember string
	if err := d.pool.QueryRow(t.Context(), `SELECT id FROM control.team_memberships WHERE team_id=$1 AND identity_id=$2`, team.ID, owner).Scan(&ownerMember); err != nil {
		t.Fatal(err)
	}
	if err := d.RecoverCompanyOwner(t.Context(), p, team.ID, ownerMember, now); err != nil {
		t.Fatal(err)
	}
	person, err := d.EnsureServiceIdentity(t.Context(), "tunnels.example.test", OIDCIdentity{Issuer: c.Issuer, Subject: "retry-member", DisplayName: "Retry member"}, now)
	if err != nil {
		t.Fatal(err)
	}
	identity := person.Identity.ID
	companyTestEligibility(t, d, c, identity, 1, true, now)
	const request = "caq_owner_retry"
	if _, err := d.pool.Exec(t.Context(), `INSERT INTO control.company_admission_requests(id,team_id,identity_connection_id,connection_revision,identity_id,subject,member_slug,state,created_at) VALUES($1,$2,$3,$4,$5,$6,'retry-member','pending',$7)`, request, team.ID, c.ID, c.Revision, identity, "directory/"+identity, now); err != nil {
		t.Fatal(err)
	}
	for _, decision := range []string{"approved", "approved", "denied", "approved"} {
		if err := d.DecideCompanyAdmission(t.Context(), p, team.ID, request, c.Revision, decision, now); err != nil {
			t.Fatal("owner decision retry/revision was rejected", decision, err)
		}
		var state string
		if err := d.pool.QueryRow(t.Context(), `SELECT state FROM control.company_admission_requests WHERE id=$1`, request).Scan(&state); err != nil || state != decision {
			t.Fatal("owner decision lost its stored state", state, err)
		}
	}
	var count int
	var member string
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*),min(id) FROM control.team_memberships WHERE team_id=$1 AND identity_id=$2`, team.ID, identity).Scan(&count, &member); err != nil || count != 1 {
		t.Fatal("admission retries created multiple memberships", count, err)
	}
	if err := d.RecoverCompanyOwner(t.Context(), p, team.ID, member, now); !errors.Is(err, ErrAuthorityAccess) {
		t.Fatal("recovery granted an exception to a nonowner", err)
	}
	companyTestEligibility(t, d, c, identity, 2, false, now)
	if err := d.DecideCompanyAdmission(t.Context(), p, team.ID, request, c.Revision, "approved", now); !errors.Is(err, ErrAuthorityAccess) {
		t.Fatal("approval retry bypassed current source eligibility", err)
	}
}
