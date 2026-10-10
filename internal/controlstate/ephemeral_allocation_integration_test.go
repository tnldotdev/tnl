package controlstate

import (
	"crypto/sha256"
	"errors"
	"regexp"
	"testing"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

func TestIntegrationEphemeralAllocationIsIdempotentAndFenced(t *testing.T) {
	fixture := issueTestEphemeralCredential(t)
	_, digest, _, err := credentials.ParseEphemeralCredential(fixture.secret)
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	request := CreatePublicURLRequest{
		TeamID: fixture.run.TeamID, DomainID: fixture.route.DomainID, ActingIdentityID: fixture.run.ActingIdentityID,
		IdempotencyKey: fixture.credential.ID + ":" + invocation, RequestDigest: sha256.Sum256([]byte("one invocation and policy")),
		Target: "http://127.0.0.1:3000", PublicURLScope: PublicURLScopeMember, Purpose: PublicURLPurposeApp,
		AllowedIPPrefixes: []string{"192.0.2.9/32"}, DNSState: PublicURLDNSPending, Ephemeral: true,
		EphemeralCredentialID: fixture.credential.ID, EphemeralTokenDigest: digest, EphemeralNamespace: fixture.credential.Namespace,
	}
	first, err := fixture.database.CreatePublicURL(t.Context(), request, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`^eph-[a-z2-7]{26}\.` + regexp.QuoteMeta(fixture.credential.Namespace) + `$`)
	if !pattern.MatchString(first.CanonicalHostname) || !first.Ephemeral || first.PublicURLScope != PublicURLScopeShared {
		t.Fatalf("ad-hoc URL = %#v", first)
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
