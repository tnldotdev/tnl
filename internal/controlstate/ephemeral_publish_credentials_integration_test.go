package controlstate

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/certificateidentity"
)

func TestIntegrationEphemeralCredentialKeepsItsScopeAndRevokesByID(t *testing.T) {
	database, now, run, _ := newPublishRunPrerequisites(t)
	route, err := database.GetPublicURLForAuthorization(t.Context(), run.PublicURLID)
	if err != nil {
		t.Fatal(err)
	}
	var namespace string
	if err := database.pool.QueryRow(t.Context(), `SELECT canonical_domain FROM control.domains WHERE id = $1`, route.DomainID).Scan(&namespace); err != nil {
		t.Fatal(err)
	}
	var role string
	if err := database.pool.QueryRow(t.Context(), `SELECT role FROM control.team_memberships WHERE id = $1`, run.MembershipID).Scan(&role); err != nil {
		t.Fatal(err)
	}
	credential, secret, err := database.CreateEphemeralCredential(t.Context(), CreateEphemeralCredentialRequest{
		TeamID: run.TeamID, DomainID: route.DomainID, Namespace: namespace,
		MembershipID: run.MembershipID, IdentityID: run.ActingIdentityID, Role: role, PolicyRevision: run.PolicyRevision,
		CertificatePlan: authorization.CertificatePlan{CacheKey: namespace, Scope: namespace,
			Identifiers: []string{"*." + namespace}, ChallengeMethod: certificateidentity.ChallengeDNS01},
		Now: now, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil || credential.Kind != PublishCredentialEphemeral || credential.PublicURLID != "" || credential.Namespace != namespace {
		t.Fatalf("issued ad-hoc credential = %#v, %v", credential, err)
	}
	selected, err := database.AuthenticateEphemeralCredential(t.Context(), secret, now)
	if err != nil || selected.ID != credential.ID {
		t.Fatalf("authenticate ad-hoc credential = %#v, %v", selected, err)
	}
	page, err := database.ListTeamPublicURLPublishCredentials(t.Context(), run.TeamID, "")
	if err != nil || len(page.Credentials) != 1 || page.Credentials[0].Kind != PublishCredentialEphemeral || page.Credentials[0].PublicURL != "" {
		t.Fatalf("team credential list = %#v, %v", page, err)
	}
	if _, err := database.RevokeEphemeralCredential(t.Context(), "another_team", credential.ID, now); !errors.Is(err, ErrPublicURLNotFound) {
		t.Fatalf("other team revoked ad-hoc credential: %v", err)
	}
	if _, err := database.RevokeEphemeralCredential(t.Context(), run.TeamID, credential.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AuthenticateEphemeralCredential(t.Context(), secret, now.Add(time.Second)); !errors.Is(err, ErrEphemeralCredential) {
		t.Fatalf("revoked ad-hoc credential authenticated: %v", err)
	}
}
