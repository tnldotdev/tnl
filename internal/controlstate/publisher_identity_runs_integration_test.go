package controlstate

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/publisheridentity"
)

func TestIntegrationEnrolledPublisherRunSurvivesEditorRemovalAndStopsOnGrantRevocation(t *testing.T) {
	database, now, run, _ := newPublishRunPrerequisites(t)
	scope := PublisherScope{TeamID: run.TeamID, PublicURLID: run.PublicURLID, Kind: "saved_url"}
	enrollment, err := database.IssuePublisherEnrollment(t.Context(), publisherEnrollmentFixture(run, scope, "publisher-run", now))
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := database.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	const audience = "https://control.example/v1/publisher/token"
	assertion, err := publisheridentity.Sign(identity.ID, identity.KeyID, audience, private, now)
	if err != nil {
		t.Fatal(err)
	}
	access, err := database.ExchangePublisherAssertion(t.Context(), identity.ID, identity.GrantID, audience, assertion, now)
	if err != nil {
		t.Fatal(err)
	}
	authorized, err := database.AuthenticatePublisherAccess(t.Context(), access.Token, now)
	if err != nil || authorized.CreatorID != run.ActingIdentityID {
		t.Fatalf("publisher actor = %+v, %v", authorized, err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.team_memberships SET removed_at = $1,
		removed_by_identity_id = $2, updated_at = $1 WHERE id = $3`, now.Add(time.Second), run.ActingIdentityID, run.MembershipID); err != nil {
		t.Fatal(err)
	}
	route, err := database.GetPublicURLForPublishRunAuthorization(t.Context(), run.PublicURLID, "identity-attempt")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := database.PublisherRunPlan(t.Context(), authorized, route, false)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := publisheridentity.SignRun(private, route.ID, "identity-attempt")
	if err != nil {
		t.Fatal(err)
	}
	key, err := database.PublisherKeyForAccess(t.Context(), authorized)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := publisheridentity.VerifyRun(key, proof, route.ID, "identity-attempt")
	if err != nil {
		t.Fatal(err)
	}
	run.IdempotencyKey, run.RequestDigest = "identity-attempt", sha256.Sum256([]byte("publisher run"))
	run.RetrySecret = secret[:]
	run.PublisherIdentityID, run.PublisherGrantID = authorized.ID, authorized.GrantID
	run.CertificateCacheKey, run.CertificateScope = plan.CacheKey, plan.Scope
	run.CertificateIdentifiers, run.CertificateChallenge = plan.Identifiers, plan.ChallengeMethod
	setup, err := database.CreatePublishRun(t.Context(), run, now.Add(2*time.Second), 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	auth := PublishRunAuthentication{PublishRunID: setup.PublishRunID, PublicURLID: route.ID,
		PublishRunNumber: setup.PublishRunNumber, PublishRunToken: setup.PublishRunToken}
	if _, err := database.HeartbeatPublishRun(t.Context(), auth, now.Add(3*time.Second), 30*time.Second, time.Minute); err != nil {
		t.Fatalf("enrolled run depended on editor membership: %v", err)
	}
	if err := database.RevokePublisherGrant(t.Context(), scope.TeamID, authorized.ID, authorized.GrantID, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.HeartbeatPublishRun(t.Context(), auth, now.Add(5*time.Second), 30*time.Second, time.Minute); !errors.Is(err, ErrPublicURLCredential) {
		t.Fatalf("revoked grant continued run: %v", err)
	}
}
