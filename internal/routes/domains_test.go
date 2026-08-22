package routes

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/state"
	"github.com/tnldotdev/tnl/internal/state/statedb"
)

type domainVerifierStub struct {
	err       error
	addresses []string
}

func TestDomainDNSRecords(t *testing.T) {
	store := &Store{domainVerifier: &domainVerifierStub{addresses: []string{"192.0.2.10"}}}
	apex := store.domainRecords("other.com", "token.domains.routes.test", true)
	if len(apex) != 3 || apex[0].Name != "_tnl.other.com." || apex[0].Type != "CNAME" ||
		apex[1].Name != "other.com." || apex[1].Type != "A" ||
		apex[2].Name != "*.other.com." || apex[2].Type != "CNAME" {
		t.Fatalf("IPv4-only apex records = %#v", apex)
	}
	subdomain := store.domainRecords("docs.other.com", "token.domains.routes.test", false)
	if len(subdomain) != 2 || subdomain[0].Name != "docs.other.com." || subdomain[0].Type != "CNAME" ||
		subdomain[1].Name != "*.docs.other.com." || subdomain[1].Type != "CNAME" {
		t.Fatalf("subdomain records = %#v", subdomain)
	}
}

func (v *domainVerifierStub) CheckDomain(context.Context, string, string, bool) error {
	return v.err
}

func (v *domainVerifierStub) IngressAddresses() []string {
	return append([]string(nil), v.addresses...)
}

func TestCustomDomainChallengeLifecycleAndTransfer(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	upsertTestPrincipal(t, ctx, queries, "owner", "Owner", 1)
	upsertTestPrincipal(t, ctx, queries, "other", "Other", 1)
	verifier := &domainVerifierStub{addresses: []string{"2001:db8::10", "192.0.2.10"}}
	store, err := NewStore(db, "routes.test", StoreConfig{
		VerificationSuffix: "domains.routes.test",
		DomainVerifier:     verifier,
	})
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := store.CreateDomainChallenge(ctx, "owner", "other.com", "first")
	if err != nil {
		t.Fatal(err)
	}
	if len(challenge.Token) < 26 || strings.HasPrefix(challenge.VerificationTarget, "claim-") ||
		challenge.VerificationTarget != challenge.Token+".domains.routes.test" || !challenge.Apex {
		t.Fatalf("challenge = %#v", challenge)
	}
	wantTypes := []string{"CNAME", "A", "AAAA", "CNAME"}
	if len(challenge.Records) != len(wantTypes) {
		t.Fatalf("records = %#v", challenge.Records)
	}
	for index, want := range wantTypes {
		if challenge.Records[index].Type != want {
			t.Fatalf("record %d = %#v", index, challenge.Records[index])
		}
	}

	verifier.err = errors.New("not propagated")
	if _, err := store.VerifyDomainChallenge(ctx, "owner", challenge.ID); !errors.Is(err, ErrDNSProofPending) {
		t.Fatalf("pending proof error = %v", err)
	}
	verifier.err = nil
	claim, err := store.VerifyDomainChallenge(ctx, "owner", challenge.ID)
	if err != nil {
		t.Fatal(err)
	}
	if claim.Hostname != "other.com" || claim.Kind != NameKindPersistentCustom || claim.State != NameStateActive {
		t.Fatalf("custom claim = %#v", claim)
	}

	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Create(ctx, "owner", "a.b.c.d.e.f.g.h.other.com", "localhost:3000", "boot", routeToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, "owner", "x.a.b.c.d.e.f.g.h.other.com", "localhost:3001", "boot", routeToken); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("ninth-level route error = %v", err)
	}

	blocked, err := store.CreateDomainChallenge(ctx, "other", "other.com", "blocked-transfer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyDomainChallenge(ctx, "other", blocked.ID); !errors.Is(err, ErrNameUnavailable) {
		t.Fatalf("active domain transfer error = %v", err)
	}
	if err := store.ReleaseHostnameClaim(ctx, "owner", claim.ID); err != nil {
		t.Fatal(err)
	}
	if routes, err := store.List(ctx, "owner"); err != nil || len(routes) != 0 {
		t.Fatalf("old owner routes = %#v, %v", routes, err)
	}
	transfer, err := store.CreateDomainChallenge(ctx, "other", "other.com", "transfer")
	if err != nil {
		t.Fatal(err)
	}
	transferred, err := store.VerifyDomainChallenge(ctx, "other", transfer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if transferred.ID != claim.ID || transferred.PrincipalID != "other" {
		t.Fatalf("transfer = %#v", transferred)
	}
}

func TestCustomDomainOverlapRejectsOnlyActivation(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	upsertTestPrincipal(t, ctx, queries, "owner", "Owner", 1)
	upsertTestPrincipal(t, ctx, queries, "other", "Other", 1)
	verifier := &domainVerifierStub{addresses: []string{"192.0.2.10"}}
	store, err := NewStore(db, "routes.test", StoreConfig{
		VerificationSuffix: "domains.routes.test", DomainVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	parent, err := store.CreateDomainChallenge(ctx, "owner", "example.com", "parent")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyDomainChallenge(ctx, "owner", parent.ID); err != nil {
		t.Fatal(err)
	}
	child, err := store.CreateDomainChallenge(ctx, "other", "docs.example.com", "child")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyDomainChallenge(ctx, "other", child.ID); !errors.Is(err, ErrNameUnavailable) {
		t.Fatalf("overlap error = %v", err)
	}
}

func TestVerifiedDomainChallengesDoNotConsumePendingQuota(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	upsertTestPrincipal(t, ctx, queries, "owner", "Owner", 1)
	store, err := NewStore(db, "routes.test", StoreConfig{
		MaxActiveHostnameClaims: 1, MaxHostnameClaimRequests: 1,
		VerificationSuffix: "domains.routes.test", DomainVerifier: &domainVerifierStub{addresses: []string{"192.0.2.10"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.CreateDomainChallenge(ctx, "owner", "first.com", "first")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyDomainChallenge(ctx, "owner", first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateDomainChallenge(ctx, "owner", "second.com", "second"); err != nil {
		t.Fatalf("challenge after verification: %v", err)
	}
}
