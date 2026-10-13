package controlstate

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
)

func publisherEnrollmentFixture(run PublishRunRequest, scope PublisherScope, name string, now time.Time) CreatePublisherEnrollmentRequest {
	return CreatePublisherEnrollmentRequest{
		Scope: scope, Name: name, Kind: "installed", EditorID: run.ActingIdentityID,
		EditorMembershipID: run.MembershipID, PolicyRevision: run.PolicyRevision, Now: now,
	}
}

func TestIntegrationPublisherEnrollmentOneUseAndScopedAssertion(t *testing.T) {
	database, now, run, _ := newPublishRunPrerequisites(t)
	scope := PublisherScope{TeamID: run.TeamID, PublicURLID: run.PublicURLID, Kind: "saved_url"}
	wrongMembership := publisherEnrollmentFixture(run, scope, "device-1", now)
	wrongMembership.EditorMembershipID = "membership_other"
	if _, err := database.IssuePublisherEnrollment(t.Context(), wrongMembership); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("wrong membership issuance = %v", err)
	}
	wrongRevision := publisherEnrollmentFixture(run, scope, "device-1", now)
	wrongRevision.PolicyRevision++
	if _, err := database.IssuePublisherEnrollment(t.Context(), wrongRevision); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("stale editor authorization = %v", err)
	}
	wrong := publisherEnrollmentFixture(run, PublisherScope{
		TeamID: "tm_other", PublicURLID: run.PublicURLID, Kind: "saved_url",
	}, "device-1", now)
	if _, err := database.IssuePublisherEnrollment(t.Context(), wrong); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("wrong team issuance = %v", err)
	}
	enrollment, err := database.IssuePublisherEnrollment(t.Context(), publisherEnrollmentFixture(run, scope, "device-1", now))
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := database.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil || identity.Scope != scope || identity.GrantID == "" {
		t.Fatalf("redeemed identity = %+v, error = %v", identity, err)
	}
	retry, err := database.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now.Add(20*time.Minute))
	if err != nil || retry != identity {
		t.Fatalf("identical retry = %+v, error = %v", retry, err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.RedeemPublisherEnrollment(t.Context(), enrollment.Key, other, now); !errors.Is(err, ErrPublisherEnrollment) {
		t.Fatalf("different key redeemed enrollment: %v", err)
	}
	if _, err := database.RedeemPublisherEnrollment(t.Context(), enrollment.Key+"a", public, now); !errors.Is(err, ErrPublisherEnrollment) {
		t.Fatalf("altered enrollment key accepted: %v", err)
	}
	const audience = "https://control.example/v1/publisher/token"
	jwt, err := publisheridentity.Sign(identity.ID, identity.KeyID, audience, private, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExchangePublisherAssertion(t.Context(), identity.ID, identity.GrantID, "https://other.example/v1/publisher/token", jwt, now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("wrong audience accepted: %v", err)
	}
	otherGrant, err := opaqueid.New(opaqueid.PublisherGrantPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExchangePublisherAssertion(t.Context(), identity.ID, otherGrant, audience, jwt, now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("unissued grant accepted: %v", err)
	}
	access, err := database.ExchangePublisherAssertion(t.Context(), identity.ID, identity.GrantID, audience, jwt, now)
	if err != nil || access.Scope != scope || access.Token == "" {
		t.Fatalf("scoped access = %+v, error = %v", access, err)
	}
	if _, err := database.ExchangePublisherAssertion(t.Context(), identity.ID, identity.GrantID, audience, jwt, now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("assertion replay accepted: %v", err)
	}
	authenticated, err := database.AuthenticatePublisherAccess(t.Context(), access.Token, now)
	if err != nil || authenticated.Scope != scope || authenticated.GrantID != identity.GrantID {
		t.Fatalf("authenticated scope = %+v, error = %v", authenticated, err)
	}
	if _, err := database.AuthenticatePublisherAccess(t.Context(), access.Token, now.Add(6*time.Minute)); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("expired access token accepted: %v", err)
	}
	if err := database.RevokePublisherIdentity(t.Context(), scope.TeamID, identity.ID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.AuthenticatePublisherAccess(t.Context(), access.Token, now.Add(time.Second)); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("revoked identity authenticated: %v", err)
	}
}

func TestIntegrationPublisherEnrollmentRejectsSuspendedURL(t *testing.T) {
	database, now, run, _ := newPublishRunPrerequisites(t)
	scope := PublisherScope{TeamID: run.TeamID, PublicURLID: run.PublicURLID, Kind: "saved_url"}
	enrollment, err := database.IssuePublisherEnrollment(t.Context(), publisherEnrollmentFixture(run, scope, "device-6", now))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.public_urls
		SET lifecycle_state = 'suspended', suspended_at = $1 WHERE id = $2`, now, scope.PublicURLID); err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now.Add(time.Second)); !errors.Is(err, ErrPublisherEnrollment) {
		t.Fatalf("suspended URL redeemed enrollment key: %v", err)
	}
	if _, err := database.IssuePublisherEnrollment(t.Context(), publisherEnrollmentFixture(run, scope, "device-7", now.Add(time.Second))); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("suspended URL issued enrollment key: %v", err)
	}
}

func TestIntegrationPublisherEnrollmentConcurrentRedemption(t *testing.T) {
	database, now, run, _ := newPublishRunPrerequisites(t)
	enrollment, err := database.IssuePublisherEnrollment(t.Context(), publisherEnrollmentFixture(run, PublisherScope{
		TeamID: run.TeamID, PublicURLID: run.PublicURLID, Kind: "saved_url",
	}, "device-2", now))
	if err != nil {
		t.Fatal(err)
	}
	const workers = 8
	results := make([]PublisherIdentity, workers)
	failures := make([]error, workers)
	var wait sync.WaitGroup
	for index := range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			public, _, err := ed25519.GenerateKey(rand.Reader)
			if err == nil {
				results[index], err = database.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
			}
			failures[index] = err
		}()
	}
	wait.Wait()
	succeeded := 0
	for index := range workers {
		if failures[index] == nil {
			succeeded++
			continue
		}
		if !errors.Is(failures[index], ErrPublisherEnrollment) {
			t.Fatalf("unexpected redemption failure: %v", failures[index])
		}
	}
	if succeeded != 1 {
		t.Fatalf("%d different public keys redeemed one enrollment, want one: %+v", succeeded, results)
	}
}

func TestIntegrationPublisherIdentityRevocationClosesLinkedRun(t *testing.T) {
	fixture := newPublishRunFixture(t)
	scope := PublisherScope{TeamID: fixture.request.TeamID, PublicURLID: fixture.request.PublicURLID, Kind: "saved_url"}
	enrollment, err := fixture.database.IssuePublisherEnrollment(t.Context(), publisherEnrollmentFixture(fixture.request, scope, "device-3", fixture.now))
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := fixture.database.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.BindPublisherRun(t.Context(), fixture.setup.PublishRunID, scope.PublicURLID, identity, fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.RevokePublisherIdentity(t.Context(), scope.TeamID, identity.ID, fixture.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.HeartbeatPublishRun(t.Context(), fixture.authentication(), fixture.now.Add(2*time.Second), time.Minute, time.Minute); !errors.Is(err, ErrPublicURLCredential) {
		t.Fatalf("heartbeat after identity revocation = %v", err)
	}
	result, err := fixture.database.GetPublicURLForAuthorization(t.Context(), scope.PublicURLID)
	if err != nil || result.OpenPublishRunID != "" {
		t.Fatalf("revoked publisher run remains open = %+v, %v", result, err)
	}
}

func TestIntegrationPublisherKeyRotationKeepsExistingRun(t *testing.T) {
	fixture := newPublishRunFixture(t)
	scope := PublisherScope{TeamID: fixture.request.TeamID, PublicURLID: fixture.request.PublicURLID, Kind: "saved_url"}
	enrollment, err := fixture.database.IssuePublisherEnrollment(t.Context(), publisherEnrollmentFixture(fixture.request, scope, "device-4", fixture.now))
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := fixture.database.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.BindPublisherRun(t.Context(), fixture.setup.PublishRunID, scope.PublicURLID, identity, fixture.now); err != nil {
		t.Fatal(err)
	}
	const tokenAudience = "https://control.example/v1/publisher/token"
	jwt, err := publisheridentity.Sign(identity.ID, identity.KeyID, tokenAudience, private, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	access, err := fixture.database.ExchangePublisherAssertion(t.Context(), identity.ID, identity.GrantID, tokenAudience, jwt, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	replacementPublic, replacementPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	replacementID, err := opaqueid.New(opaqueid.PublisherIdentityKeyPrefix)
	if err != nil {
		t.Fatal(err)
	}
	const rotationAudience = "https://control.example/v1/publisher/keys/rotate"
	proof, err := publisheridentity.Sign(identity.ID, replacementID, rotationAudience, replacementPrivate, fixture.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.RotatePublisherKey(t.Context(), access.Token, replacementID, rotationAudience, replacementPublic, proof, fixture.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.AuthenticatePublisherAccess(t.Context(), access.Token, fixture.now.Add(time.Second)); err != nil {
		t.Fatalf("current publisher access stopped after rotation: %v", err)
	}
	old, err := publisheridentity.Sign(identity.ID, identity.KeyID, tokenAudience, private, fixture.now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.ExchangePublisherAssertion(t.Context(), identity.ID, identity.GrantID, tokenAudience, old, fixture.now.Add(2*time.Second)); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("retired key exchanged a new access token: %v", err)
	}
	newAssertion, err := publisheridentity.Sign(identity.ID, replacementID, tokenAudience, replacementPrivate, fixture.now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.ExchangePublisherAssertion(t.Context(), identity.ID, identity.GrantID, tokenAudience, newAssertion, fixture.now.Add(2*time.Second)); err != nil {
		t.Fatalf("new key could not exchange token: %v", err)
	}
	if _, err := fixture.database.HeartbeatPublishRun(t.Context(), fixture.authentication(), fixture.now.Add(2*time.Second), time.Minute, time.Minute); err != nil {
		t.Fatalf("run heartbeat after signing key rotation: %v", err)
	}
}

func TestIntegrationPublisherGrantsRemainSeparate(t *testing.T) {
	fixture := newPublishRunFixture(t)
	saved := PublisherScope{TeamID: fixture.request.TeamID, PublicURLID: fixture.request.PublicURLID, Kind: "saved_url"}
	enrollment, err := fixture.database.IssuePublisherEnrollment(t.Context(), publisherEnrollmentFixture(fixture.request, saved, "device-5", fixture.now))
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := fixture.database.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.database.BindPublisherRun(t.Context(), fixture.setup.PublishRunID, saved.PublicURLID, identity, fixture.now); err != nil {
		t.Fatal(err)
	}
	namespace := PublisherScope{TeamID: saved.TeamID, DomainID: "domain_session", Namespace: "session.example.test", Kind: "namespace"}
	grantID, err := fixture.database.CreatePublisherGrant(t.Context(), CreatePublisherGrantRequest{
		PublisherIdentityID: identity.ID, Scope: namespace, EditorID: fixture.request.ActingIdentityID,
		EditorMembershipID: fixture.request.MembershipID, PolicyRevision: fixture.request.PolicyRevision, Now: fixture.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if grantID == identity.GrantID {
		t.Fatal("namespace grant reused the saved URL grant")
	}
	recovered, err := fixture.database.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, fixture.now.Add(20*time.Minute))
	if err != nil || recovered != identity {
		t.Fatalf("initial grant changed after adding another grant: %+v, %v", recovered, err)
	}
	if _, err := fixture.database.CreatePublisherGrant(t.Context(), CreatePublisherGrantRequest{
		PublisherIdentityID: identity.ID, Scope: namespace, EditorID: fixture.request.ActingIdentityID,
		EditorMembershipID: fixture.request.MembershipID, PolicyRevision: fixture.request.PolicyRevision, Now: fixture.now,
	}); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("duplicate active namespace grant accepted: %v", err)
	}
	const audience = "https://control.example/v1/publisher/token"
	jwt, err := publisheridentity.Sign(identity.ID, identity.KeyID, audience, private, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	scoped, err := fixture.database.ExchangePublisherAssertion(t.Context(), identity.ID, grantID, audience, jwt, fixture.now)
	if err != nil || scoped.Scope != namespace {
		t.Fatalf("namespace access = %+v, %v", scoped, err)
	}
	if err := fixture.database.RevokePublisherGrant(t.Context(), saved.TeamID, identity.ID, identity.GrantID, fixture.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.HeartbeatPublishRun(t.Context(), fixture.authentication(), fixture.now.Add(2*time.Second), time.Minute, time.Minute); !errors.Is(err, ErrPublicURLCredential) {
		t.Fatalf("saved URL run survived grant revocation: %v", err)
	}
	if _, err := fixture.database.AuthenticatePublisherAccess(t.Context(), scoped.Token, fixture.now.Add(2*time.Second)); err != nil {
		t.Fatalf("separate namespace grant lost access: %v", err)
	}
}
