package controlstate

import (
	"crypto/sha256"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

func testEphemeralAllocationRequest(t *testing.T, fixture testEphemeralCredentialScope) CreatePublicURLRequest {
	t.Helper()
	_, digest, _, err := credentials.ParseEphemeralCredential(fixture.secret)
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	return CreatePublicURLRequest{
		TeamID: fixture.run.TeamID, DomainID: fixture.route.DomainID, ActingIdentityID: fixture.run.ActingIdentityID,
		IdempotencyKey: fixture.credential.ID + ":" + invocation, RequestDigest: sha256.Sum256([]byte("one invocation and policy")),
		Target: "http://127.0.0.1:3000", PublicURLScope: PublicURLScopeMember, Purpose: PublicURLPurposeApp,
		AllowedIPPrefixes: []string{"192.0.2.9/32"}, DNSState: PublicURLDNSPending, Ephemeral: true,
		EphemeralCredentialID: fixture.credential.ID, EphemeralTokenDigest: digest, EphemeralNamespace: fixture.credential.Namespace,
		EphemeralInvocationID: invocation,
	}
}

func TestIntegrationEphemeralAllocationIsIdempotentAndFenced(t *testing.T) {
	fixture := issueTestEphemeralCredential(t)
	request := testEphemeralAllocationRequest(t, fixture)
	first, err := fixture.database.CreatePublicURL(t.Context(), request, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`^eph-[a-z2-7]{26}\.` + regexp.QuoteMeta(fixture.credential.Namespace) + `$`)
	if !pattern.MatchString(first.CanonicalHostname) || !first.Ephemeral || first.PublicURLScope != PublicURLScopeShared {
		t.Fatalf("ad-hoc URL = %#v", first)
	}
	var allocatedBy, invocation string
	if err := fixture.database.pool.QueryRow(t.Context(), `SELECT credential_id, invocation_id FROM control.ephemeral_public_url_allocations WHERE public_url_id = $1`, first.ID).Scan(&allocatedBy, &invocation); err != nil ||
		allocatedBy != fixture.credential.ID || invocation != request.EphemeralInvocationID {
		t.Fatalf("persisted ad-hoc allocation = %q, %q, %v", allocatedBy, invocation, err)
	}
	repeated, err := fixture.database.CreatePublicURL(t.Context(), request, fixture.now)
	if err != nil || repeated.ID != first.ID || repeated.CanonicalHostname != first.CanonicalHostname {
		t.Fatalf("allocation retry = %#v, %v", repeated, err)
	}
	changed := request
	changed.Target = "http://127.0.0.1:4000"
	changed.RequestDigest = sha256.Sum256([]byte("different target"))
	if _, err := fixture.database.CreatePublicURL(t.Context(), changed, fixture.now); !errors.Is(err, ErrPublicURLIdempotency) {
		t.Fatalf("changed invocation reused its URL: %v", err)
	}
	nextInvocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	request.IdempotencyKey = fixture.credential.ID + ":" + nextInvocation
	request.EphemeralInvocationID = nextInvocation
	second, err := fixture.database.CreatePublicURL(t.Context(), request, fixture.now)
	if err != nil || second.ID == first.ID || second.CanonicalHostname == first.CanonicalHostname || !pattern.MatchString(second.CanonicalHostname) {
		t.Fatalf("next invocation = %#v, %v", second, err)
	}
	if _, err := fixture.database.RevokeEphemeralCredential(t.Context(), fixture.run.TeamID, fixture.credential.ID, fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.CreatePublicURL(t.Context(), request, fixture.now); !errors.Is(err, ErrPublicURLAccess) {
		t.Fatalf("revoked credential retried an allocation: %v", err)
	}
}

func TestIntegrationEphemeralPublishRunClosesOnCredentialRevocation(t *testing.T) {
	fixture := issueTestEphemeralCredential(t)
	allocation := testEphemeralAllocationRequest(t, fixture)
	route, err := fixture.database.CreatePublicURL(t.Context(), allocation, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	_, _, retrySecret, err := credentials.ParseEphemeralCredential(fixture.secret)
	if err != nil {
		t.Fatal(err)
	}
	plan := fixture.credential.CertificatePlan
	other, _, err := fixture.database.CreateEphemeralCredential(t.Context(), CreateEphemeralCredentialRequest{
		TeamID: fixture.run.TeamID, DomainID: fixture.route.DomainID, Namespace: fixture.credential.Namespace,
		MembershipID: fixture.run.MembershipID, IdentityID: fixture.run.ActingIdentityID,
		Role: fixture.credential.IssuedRole, PolicyRevision: fixture.run.PolicyRevision,
		CertificatePlan: plan, Now: fixture.now, ExpiresAt: fixture.now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	run := PublishRunRequest{
		PublicURLID: route.ID, TeamID: route.TeamID, MembershipID: fixture.run.MembershipID,
		ActingIdentityID: fixture.run.ActingIdentityID, RetrySecret: retrySecret,
		IdempotencyKey: "ad-hoc-run", RequestDigest: sha256.Sum256([]byte("ad-hoc-run")),
		PolicyRevision: fixture.run.PolicyRevision, ExpectedMutationRevision: route.MutationRevision,
		CertificateCacheKey: plan.CacheKey, CertificateScope: plan.Scope,
		CertificateIdentifiers: plan.Identifiers, CertificateChallenge: plan.ChallengeMethod,
		PublishCredentialID: fixture.credential.ID,
	}
	foreign := run
	foreign.PublishCredentialID = other.ID
	foreign.IdempotencyKey = "foreign-ad-hoc-run"
	foreign.RequestDigest = sha256.Sum256([]byte(foreign.IdempotencyKey))
	if _, err := fixture.database.CreatePublishRun(t.Context(), foreign, fixture.now, 30*time.Second, time.Minute); !errors.Is(err, ErrPublicURLCredential) {
		t.Fatalf("another credential started the ad-hoc publish run: %v", err)
	}
	setup, err := fixture.database.CreatePublishRun(t.Context(), run, fixture.now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	authentication := PublishRunAuthentication{PublishRunID: setup.PublishRunID, PublicURLID: route.ID,
		PublishRunNumber: setup.PublishRunNumber, PublishRunToken: setup.PublishRunToken}
	if _, err := fixture.database.HeartbeatPublishRun(t.Context(), authentication, fixture.now, 30*time.Second, time.Minute); err != nil {
		t.Fatalf("active ad-hoc run lost authority: %v", err)
	}
	if _, err := fixture.database.RevokeEphemeralCredential(t.Context(), fixture.run.TeamID, fixture.credential.ID, fixture.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.database.HeartbeatPublishRun(t.Context(), authentication, fixture.now.Add(2*time.Second), 30*time.Second, time.Minute); !errors.Is(err, ErrPublicURLCredential) {
		t.Fatalf("revoked ad-hoc run heartbeat = %v", err)
	}
}
