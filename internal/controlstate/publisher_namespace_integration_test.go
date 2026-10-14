package controlstate

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
)

func TestIntegrationEnrolledNamespaceOwnsAllocationAndRunAfterEditorLeaves(t *testing.T) {
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
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.team_memberships SET removed_at = $1,
		removed_by_identity_id = $2, updated_at = $1 WHERE id = $3`, now.Add(time.Second), seed.ActingIdentityID, seed.MembershipID); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.identities SET disabled_at = $1, updated_at = $1 WHERE id = $2`, now.Add(time.Second), seed.ActingIdentityID); err != nil {
		t.Fatal(err)
	}
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	request := CreatePublicURLRequest{
		TeamID: scope.TeamID, DomainID: scope.DomainID, ActingIdentityID: seed.ActingIdentityID,
		IdempotencyKey: owner.ID + ":" + invocation, RequestDigest: sha256.Sum256([]byte("allocated by owner")),
		Target: "http://127.0.0.1:3000", PublicURLScope: PublicURLScopeShared, Purpose: PublicURLPurposeApp,
		ManagedURLMode: naming.ManagedURLModeSimple, DNSState: PublicURLDNSPending, Ephemeral: true,
		PublisherIdentityID: owner.ID, PublisherGrantID: owner.GrantID,
		PublisherNamespace: scope.Namespace, PublisherInvocationID: invocation,
	}
	route, err := database.CreatePublicURL(t.Context(), request, now.Add(2*time.Second))
	if err != nil || !route.Ephemeral || route.PublicURLScope != PublicURLScopeShared ||
		!strings.HasSuffix(route.CanonicalHostname, "."+scope.Namespace) {
		t.Fatalf("namespace allocation = %+v, %v", route, err)
	}
	retry, err := database.CreatePublicURL(t.Context(), request, now.Add(3*time.Second))
	if err != nil || retry.ID != route.ID {
		t.Fatalf("allocation retry = %+v, %v", retry, err)
	}
	if owned, err := database.PublisherMayStartRun(t.Context(), other, route.ID); err != nil || owned {
		t.Fatalf("another identity owns allocation: %t, %v", owned, err)
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
	run := PublishRunRequest{PublicURLID: route.ID, TeamID: scope.TeamID, ActingIdentityID: seed.ActingIdentityID,
		PublisherIdentityID: owner.ID, PublisherGrantID: owner.GrantID, RetrySecret: retrySecret[:],
		IdempotencyKey: "namespace-run", RequestDigest: sha256.Sum256([]byte("namespace-run")),
		PolicyRevision: uint64(route.PolicyRevision), ExpectedMutationRevision: route.MutationRevision,
		CertificateCacheKey: plan.CacheKey, CertificateScope: plan.Scope,
		CertificateIdentifiers: plan.Identifiers, CertificateChallenge: plan.ChallengeMethod}
	foreign := run
	foreign.PublisherIdentityID, foreign.PublisherGrantID = other.ID, other.GrantID
	foreign.IdempotencyKey = "foreign-run"
	if _, err := database.CreatePublishRun(t.Context(), foreign, now.Add(3*time.Second), 30*time.Second, time.Minute); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatalf("other publisher started allocated run: %v", err)
	}
	setup, err := database.CreatePublishRun(t.Context(), run, now.Add(3*time.Second), 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.DeleteAuthorizedPublicURL(t.Context(), AuthorizedPublicURLDeleteRequest{
		PublicURLID: route.ID, TeamID: scope.TeamID, ActingIdentityID: seed.ActingIdentityID,
		PublisherIdentityID: other.ID, PublisherGrantID: other.GrantID,
	}, now.Add(4*time.Second)); !errors.Is(err, ErrPublicURLAccess) {
		t.Fatalf("other publisher deleted allocation: %v", err)
	}
	if err := database.RevokePublisherGrant(t.Context(), scope.TeamID, owner.ID, owner.GrantID, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	auth := PublishRunAuthentication{PublishRunID: setup.PublishRunID, PublicURLID: route.ID,
		PublishRunNumber: setup.PublishRunNumber, PublishRunToken: setup.PublishRunToken}
	if _, err := database.HeartbeatPublishRun(t.Context(), auth, now.Add(5*time.Second), 30*time.Second, time.Minute); !errors.Is(err, ErrPublicURLCredential) {
		t.Fatalf("revoked namespace grant kept run open: %v", err)
	}
}

func TestIntegrationMemberNamespaceAllocationSurvivesEditorRemovalAndDeletes(t *testing.T) {
	database, now, seed, _ := newPublishRunPrerequisites(t)
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.teams SET kind = 'organization' WHERE id = $1`, seed.TeamID); err != nil {
		t.Fatal(err)
	}
	scope := PublisherScope{TeamID: seed.TeamID, DomainID: "domain_session",
		Namespace: "member-session.session.example.test", Kind: "namespace"}
	enrollment, err := database.IssuePublisherEnrollment(t.Context(), publisherEnrollmentFixture(seed, scope, "member-publisher", now))
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := database.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.team_memberships SET removed_at = $1,
		removed_by_identity_id = $2, updated_at = $1 WHERE id = $3`, now.Add(time.Second), seed.ActingIdentityID, seed.MembershipID); err != nil {
		t.Fatal(err)
	}
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	route, err := database.CreatePublicURL(t.Context(), CreatePublicURLRequest{
		TeamID: scope.TeamID, DomainID: scope.DomainID, ActingIdentityID: seed.ActingIdentityID,
		IdempotencyKey: identity.ID + ":" + invocation, RequestDigest: sha256.Sum256([]byte("member allocation")),
		Target: "http://127.0.0.1:3000", PublicURLScope: PublicURLScopeMember, Purpose: PublicURLPurposeApp,
		ManagedURLMode: naming.ManagedURLModeSimple, DNSState: PublicURLDNSPending, Ephemeral: true,
		PublisherIdentityID: identity.ID, PublisherGrantID: identity.GrantID,
		PublisherNamespace: scope.Namespace, PublisherInvocationID: invocation,
	}, now.Add(2*time.Second))
	if err != nil || route.PublicURLScope != PublicURLScopeMember || route.MembershipID != seed.MembershipID ||
		!strings.HasSuffix(route.CanonicalHostname, "."+scope.Namespace) {
		t.Fatalf("member namespace allocation = %+v, %v", route, err)
	}
	if err := database.DeleteAuthorizedPublicURL(t.Context(), AuthorizedPublicURLDeleteRequest{
		PublicURLID: route.ID, TeamID: scope.TeamID, ActingIdentityID: seed.ActingIdentityID,
		PublisherIdentityID: identity.ID, PublisherGrantID: identity.GrantID,
	}, now.Add(3*time.Second)); err != nil {
		t.Fatalf("delete allocated member URL: %v", err)
	}
	if _, err := database.GetPublicURLForAuthorization(t.Context(), route.ID); !errors.Is(err, ErrPublicURLNotFound) {
		t.Fatalf("temporary URL survived cleanup: %v", err)
	}
}
