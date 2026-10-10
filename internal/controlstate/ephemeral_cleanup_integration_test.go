package controlstate

import (
	"errors"
	"testing"
	"time"
)

func TestIntegrationOnlyAllocatingCredentialCanRemoveEphemeralURL(t *testing.T) {
	fixture := issueTestEphemeralCredential(t)
	allocation := testEphemeralAllocationRequest(t, fixture)
	url, err := fixture.database.CreatePublicURL(t.Context(), allocation, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	other, otherToken, err := fixture.database.CreateEphemeralCredential(t.Context(), CreateEphemeralCredentialRequest{
		TeamID: fixture.run.TeamID, DomainID: fixture.route.DomainID, Namespace: fixture.credential.Namespace,
		MembershipID: fixture.run.MembershipID, IdentityID: fixture.run.ActingIdentityID,
		Role: fixture.credential.IssuedRole, PolicyRevision: fixture.run.PolicyRevision,
		CertificatePlan: fixture.credential.CertificatePlan,
		Now:             fixture.now, ExpiresAt: fixture.now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.DeleteAuthorizedPublicURL(t.Context(), AuthorizedPublicURLDeleteRequest{
		PublicURLID: url.ID, TeamID: fixture.run.TeamID, ActingIdentityID: fixture.run.ActingIdentityID,
		EphemeralCredential: otherToken,
	}, fixture.now); !errors.Is(err, ErrPublicURLAccess) {
		t.Fatalf("credential %s deleted another credential's URL: %v", other.ID, err)
	}
	if err := fixture.database.DeleteAuthorizedPublicURL(t.Context(), AuthorizedPublicURLDeleteRequest{
		PublicURLID: url.ID, TeamID: fixture.run.TeamID, ActingIdentityID: fixture.run.ActingIdentityID,
		EphemeralCredential: fixture.secret,
	}, fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.GetPublicURLForAuthorization(t.Context(), url.ID); !errors.Is(err, ErrPublicURLNotFound) {
		t.Fatalf("ad-hoc URL remained available after close: %v", err)
	}
	var state string
	if err := fixture.database.pool.QueryRow(t.Context(), `SELECT lifecycle_state FROM control.public_urls WHERE id = $1`, url.ID).Scan(&state); err != nil || state != string(PublicURLLifecycleDeleted) {
		t.Fatalf("ad-hoc URL lifecycle after close = %q, %v", state, err)
	}
}
