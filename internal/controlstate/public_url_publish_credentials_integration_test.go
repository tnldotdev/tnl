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
