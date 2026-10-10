package controlstate

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/credentials"
)

func TestIntegrationPublishCredentialRevocationClosesActiveRun(t *testing.T) {
	database, now, run, _ := newPublishRunPrerequisites(t)
	route, err := database.GetPublicURLForAuthorization(t.Context(), run.PublicURLID)
	if err != nil {
		t.Fatal(err)
	}
	credential, secret, err := database.CreatePublicURLPublishCredential(t.Context(), CreatePublicURLPublishCredentialRequest{
		PublicURLID: route.ID, TeamID: run.TeamID, IdentityID: run.ActingIdentityID, MembershipID: run.MembershipID,
		PolicyRevision: run.PolicyRevision, Target: route.Target,
		CertificatePlan: authorization.CertificatePlan{
			CacheKey: run.CertificateCacheKey, Scope: run.CertificateScope,
			Identifiers: run.CertificateIdentifiers, ChallengeMethod: run.CertificateChallenge,
		}, Now: now, ExpiresAt: now.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	selected, retrySecret, err := database.AuthenticatePublicURLPublishCredential(t.Context(), secret, now)
	if err != nil || selected.ID != credential.ID || len(retrySecret) != 32 {
		t.Fatalf("authenticate publish credential = %#v, %v", selected, err)
	}
	if err := database.ValidatePublicURLPublishCredential(t.Context(), selected, route); err != nil {
		t.Fatal(err)
	}
	if _, _, err := database.AuthenticatePublicURLPublishCredential(t.Context(), credentials.PublicURLPublishCredential(secret.String()+"x"), now); !errors.Is(err, ErrPublicURLPublishCredential) {
		t.Fatalf("altered credential accepted: %v", err)
	}
	run.RetrySecret = retrySecret
	run.PublishCredentialID = credential.ID
	setup, err := database.CreatePublishRun(t.Context(), run, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.RevokePublicURLPublishCredential(t.Context(), route.ID, credential.ID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := database.AuthenticatePublicURLPublishCredential(t.Context(), secret, now.Add(2*time.Second)); !errors.Is(err, ErrPublicURLPublishCredential) {
		t.Fatalf("revoked credential accepted: %v", err)
	}
	auth := PublishRunAuthentication{PublishRunID: setup.PublishRunID, PublicURLID: route.ID, PublishRunNumber: setup.PublishRunNumber, PublishRunToken: setup.PublishRunToken}
	if _, err := database.HeartbeatPublishRun(t.Context(), auth, now.Add(2*time.Second), 30*time.Second, time.Minute); !errors.Is(err, ErrPublicURLCredential) {
		t.Fatalf("revoked run heartbeat: %v", err)
	}
	closed, err := database.GetPublicURLForAuthorization(t.Context(), route.ID)
	if err != nil || closed.OpenPublishRunID != "" {
		t.Fatalf("revoked run still open = %#v, %v", closed, err)
	}
}

func TestIntegrationTargetlessSavedAppCredentialCanPublishAndHeartbeat(t *testing.T) {
	database, now, run, _ := newPublishRunPrerequisites(t)
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.public_urls SET target = '' WHERE id = $1`, run.PublicURLID); err != nil {
		t.Fatal(err)
	}
	route, err := database.GetPublicURLForAuthorization(t.Context(), run.PublicURLID)
	if err != nil || route.Target != "" {
		t.Fatalf("targetless saved URL = %#v, %v", route, err)
	}
	credential, token, err := database.CreatePublicURLPublishCredential(t.Context(), CreatePublicURLPublishCredentialRequest{
		PublicURLID: route.ID, TeamID: run.TeamID, IdentityID: run.ActingIdentityID, MembershipID: run.MembershipID,
		PolicyRevision: run.PolicyRevision,
		CertificatePlan: authorization.CertificatePlan{
			CacheKey: run.CertificateCacheKey, Scope: run.CertificateScope,
			Identifiers: run.CertificateIdentifiers, ChallengeMethod: run.CertificateChallenge,
		}, Now: now, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil || credential.Target != "" {
		t.Fatalf("targetless credential = %#v, %v", credential, err)
	}
	selected, retrySecret, err := database.AuthenticatePublicURLPublishCredential(t.Context(), token, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.ValidatePublicURLPublishCredential(t.Context(), selected, route); err != nil {
		t.Fatal(err)
	}
	run.RetrySecret, run.PublishCredentialID = retrySecret, credential.ID
	setup, err := database.CreatePublishRun(t.Context(), run, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	auth := PublishRunAuthentication{PublishRunID: setup.PublishRunID, PublicURLID: route.ID, PublishRunNumber: setup.PublishRunNumber, PublishRunToken: setup.PublishRunToken}
	if _, err := database.HeartbeatPublishRun(t.Context(), auth, now.Add(time.Second), 30*time.Second, time.Minute); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationTeamPublishCredentialPagesAndLookup(t *testing.T) {
	database, now, run, _ := newPublishRunPrerequisites(t)
	route, err := database.GetPublicURLForAuthorization(t.Context(), run.PublicURLID)
	if err != nil {
		t.Fatal(err)
	}
	var last PublicURLPublishCredential
	for index := range 102 {
		createdAt := now.Add(time.Duration(index) * time.Millisecond)
		last, _, err = database.CreatePublicURLPublishCredential(t.Context(), CreatePublicURLPublishCredentialRequest{
			PublicURLID: route.ID, TeamID: run.TeamID, IdentityID: run.ActingIdentityID, MembershipID: run.MembershipID,
			PolicyRevision: run.PolicyRevision, Target: route.Target,
			CertificatePlan: authorization.CertificatePlan{
				CacheKey: run.CertificateCacheKey, Scope: run.CertificateScope,
				Identifiers: run.CertificateIdentifiers, ChallengeMethod: run.CertificateChallenge,
			}, Now: createdAt, ExpiresAt: createdAt.Add(time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	first, err := database.ListTeamPublicURLPublishCredentials(t.Context(), run.TeamID, "")
	if err != nil || len(first.Credentials) != 100 || first.NextCursor == "" {
		t.Fatalf("first credential page = %d, cursor %q, err %v", len(first.Credentials), first.NextCursor, err)
	}
	second, err := database.ListTeamPublicURLPublishCredentials(t.Context(), run.TeamID, first.NextCursor)
	if err != nil || len(second.Credentials) != 2 || second.NextCursor != "" {
		t.Fatalf("second credential page = %d, cursor %q, err %v", len(second.Credentials), second.NextCursor, err)
	}
	seen := make(map[string]bool, 102)
	for _, entry := range append(first.Credentials, second.Credentials...) {
		if seen[entry.ID] || entry.PublicURLID != route.ID || entry.PublicURL != "https://"+route.CanonicalHostname {
			t.Fatalf("incorrect credential scope in list: %#v", entry)
		}
		seen[entry.ID] = true
	}
	byID, err := database.PublicURLPublishCredentialByID(t.Context(), last.ID)
	if err != nil || byID.ID != last.ID || byID.PublicURLID != route.ID {
		t.Fatalf("credential lookup = %#v, %v", byID, err)
	}
	otherTeam, err := database.ListTeamPublicURLPublishCredentials(t.Context(), "team_other", "")
	if err != nil || len(otherTeam.Credentials) != 0 {
		t.Fatalf("cross-team list = %#v, %v", otherTeam, err)
	}
}
