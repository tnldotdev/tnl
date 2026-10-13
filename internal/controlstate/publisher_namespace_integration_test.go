package controlstate

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
)

func TestIntegrationNamespacePublisherAllocatesAndCleansUpAfterEnrollerLeaves(t *testing.T) {
	database, now, run, _ := newPublishRunPrerequisites(t)
	scope := PublisherScope{TeamID: run.TeamID, DomainID: "domain_session", Namespace: "session.example.test", Kind: "namespace"}
	enrollment, err := database.IssuePublisherEnrollment(t.Context(), publisherEnrollmentFixture(run, scope, "device-namespace", now))
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
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.team_memberships SET removed_at = $1,
		removed_by_identity_id = $2, updated_at = $1 WHERE id = $3`, now.Add(time.Second), run.ActingIdentityID, run.MembershipID); err != nil {
		t.Fatal(err)
	}
	authorized, err := database.AuthenticatePublisherAccess(t.Context(), access.Token, now.Add(2*time.Second))
	if err != nil || authorized.Scope != scope {
		t.Fatalf("team-owned namespace grant = %+v, %v", authorized, err)
	}
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	request := CreatePublicURLRequest{
		TeamID: scope.TeamID, DomainID: scope.DomainID, ActingIdentityID: authorized.CreatorID,
		IdempotencyKey: identity.ID + ":" + invocation, RequestDigest: sha256.Sum256([]byte("namespace invocation")),
		Target: "http://127.0.0.1:3000", PublicURLScope: PublicURLScopeMember, Purpose: PublicURLPurposeApp,
		ManagedURLMode: naming.ManagedURLModeSimple, DNSState: PublicURLDNSPending, Ephemeral: true,
		PublisherIdentityID: identity.ID, PublisherGrantID: identity.GrantID,
		PublisherNamespace: scope.Namespace, PublisherInvocationID: invocation,
	}
	route, err := database.CreatePublicURL(t.Context(), request, now.Add(2*time.Second))
	if err != nil || route.Namespace != scope.Namespace || !route.Ephemeral || route.PublicURLScope != PublicURLScopeShared {
		t.Fatalf("namespace allocation = %+v, %v", route, err)
	}
	if !regexp.MustCompile(`^eph-[a-z2-7]{26}\.session\.example\.test$`).MatchString(route.CanonicalHostname) {
		t.Fatalf("allocated hostname escaped the exact namespace: %q", route.CanonicalHostname)
	}
	var allocatedBy, allocatedGrant, recordedInvocation string
	if err := database.pool.QueryRow(t.Context(), `SELECT publisher_identity_id, publisher_grant_id, invocation_id
		FROM control.publisher_namespace_allocations WHERE public_url_id = $1`, route.ID).Scan(&allocatedBy, &allocatedGrant, &recordedInvocation); err != nil ||
		allocatedBy != identity.ID || allocatedGrant != identity.GrantID || recordedInvocation != invocation {
		t.Fatalf("saved invocation ownership = %q %q %q, %v", allocatedBy, allocatedGrant, recordedInvocation, err)
	}
	retry, err := database.CreatePublicURL(t.Context(), request, now.Add(3*time.Second))
	if err != nil || retry.ID != route.ID {
		t.Fatalf("invocation retry = %+v, %v", retry, err)
	}
	changed := request
	changed.PublisherNamespace = "other.example.test"
	if _, err := database.CreatePublicURL(t.Context(), changed, now.Add(3*time.Second)); !errors.Is(err, ErrPublicURLAccess) {
		t.Fatalf("cross-namespace allocation = %v", err)
	}
	changed = request
	changed.Target = "http://127.0.0.1:4000"
	changed.RequestDigest = sha256.Sum256([]byte("different invocation target"))
	if _, err := database.CreatePublicURL(t.Context(), changed, now.Add(3*time.Second)); !errors.Is(err, ErrPublicURLIdempotency) {
		t.Fatalf("changed invocation reused its URL: %v", err)
	}
	if err := database.DeleteAuthorizedPublicURL(t.Context(), AuthorizedPublicURLDeleteRequest{
		PublicURLID: route.ID, TeamID: scope.TeamID, ActingIdentityID: authorized.CreatorID,
		PublisherIdentityID: identity.ID, PublisherGrantID: identity.GrantID,
	}, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.GetPublicURLForAuthorization(t.Context(), route.ID); !errors.Is(err, ErrPublicURLNotFound) {
		t.Fatalf("ad-hoc URL survived cleanup: %v", err)
	}
	var lifecycle string
	if err := database.pool.QueryRow(t.Context(), `SELECT lifecycle_state FROM control.public_urls WHERE id=$1`, route.ID).Scan(&lifecycle); err != nil || lifecycle != string(PublicURLLifecycleDeleted) {
		t.Fatalf("temporary URL lifecycle = %q, %v", lifecycle, err)
	}
}

func TestIntegrationNamespaceGrantOwnsOnlyItsAllocationAndRun(t *testing.T) {
	database, now, seed, _ := newPublishRunPrerequisites(t)
	scope := PublisherScope{TeamID: seed.TeamID, DomainID: "domain_session", Namespace: "session.example.test", Kind: "namespace"}
	makeIdentity := func(name string) (PublisherIdentity, ed25519.PublicKey, ed25519.PrivateKey) {
		t.Helper()
		enrollment, err := database.IssuePublisherEnrollment(t.Context(), publisherEnrollmentFixture(seed, scope, name, now))
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
		return identity, public, private
	}
	owner, public, private := makeIdentity("namespace-owner")
	other, _, _ := makeIdentity("namespace-other")
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	route, err := database.CreatePublicURL(t.Context(), CreatePublicURLRequest{
		TeamID: scope.TeamID, DomainID: scope.DomainID, ActingIdentityID: seed.ActingIdentityID,
		IdempotencyKey: owner.ID + ":" + invocation, RequestDigest: sha256.Sum256([]byte("allocated by owner")),
		Target: "http://127.0.0.1:3000", PublicURLScope: PublicURLScopeMember, Purpose: PublicURLPurposeApp,
		ManagedURLMode: naming.ManagedURLModeSimple, DNSState: PublicURLDNSPending, Ephemeral: true,
		PublisherIdentityID: owner.ID, PublisherGrantID: owner.GrantID,
		PublisherNamespace: scope.Namespace, PublisherInvocationID: invocation,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.DeleteAuthorizedPublicURL(t.Context(), AuthorizedPublicURLDeleteRequest{
		PublicURLID: route.ID, TeamID: scope.TeamID, ActingIdentityID: seed.ActingIdentityID,
		PublisherIdentityID: other.ID, PublisherGrantID: other.GrantID,
	}, now); !errors.Is(err, ErrPublicURLAccess) {
		t.Fatalf("another identity deleted the allocated URL: %v", err)
	}
	plan, err := database.PublisherRunPlan(t.Context(), owner, route, true)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := publisheridentity.SignRun(private, route.ID, "namespace-run")
	if err != nil {
		t.Fatal(err)
	}
	retrySecret, err := publisheridentity.VerifyRun(public, proof, route.ID, "namespace-run")
	if err != nil {
		t.Fatal(err)
	}
	request := PublishRunRequest{
		PublicURLID: route.ID, TeamID: scope.TeamID, ActingIdentityID: seed.ActingIdentityID,
		PublisherIdentityID: owner.ID, PublisherGrantID: owner.GrantID, RetrySecret: retrySecret[:],
		IdempotencyKey: "namespace-run", RequestDigest: sha256.Sum256([]byte("namespace-run")),
		PolicyRevision: uint64(route.PolicyRevision), ExpectedMutationRevision: route.MutationRevision,
		CertificateCacheKey: plan.CacheKey, CertificateScope: plan.Scope,
		CertificateIdentifiers: plan.Identifiers, CertificateChallenge: plan.ChallengeMethod,
	}
	foreign := request
	foreign.PublisherIdentityID, foreign.PublisherGrantID = other.ID, other.GrantID
	foreign.IdempotencyKey = "foreign-namespace-run"
	if _, err := database.CreatePublishRun(t.Context(), foreign, now, 30*time.Second, time.Minute); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("another namespace grant started the URL's run: %v", err)
	}
	setup, err := database.CreatePublishRun(t.Context(), request, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	connection := PublishRunAuthentication{PublishRunID: setup.PublishRunID, PublicURLID: route.ID,
		PublishRunNumber: setup.PublishRunNumber, PublishRunToken: setup.PublishRunToken}
	if _, err := database.HeartbeatPublishRun(t.Context(), connection, now, 30*time.Second, time.Minute); err != nil {
		t.Fatalf("active namespace run lost its grant: %v", err)
	}
	if err := database.RevokePublisherGrant(t.Context(), scope.TeamID, owner.ID, owner.GrantID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.HeartbeatPublishRun(t.Context(), connection, now.Add(2*time.Second), 30*time.Second, time.Minute); !errors.Is(err, ErrPublicURLCredential) {
		t.Fatalf("revoked namespace grant kept the run open: %v", err)
	}
}
