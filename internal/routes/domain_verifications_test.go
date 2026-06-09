package routes

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/state"
	"github.com/tnldotdev/tnl/internal/state/statedb"
	"tailscale.com/types/key"
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

func TestCustomDomainVerificationLifecycleAndTransfer(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	upsertTestIdentity(t, ctx, queries, "owner", "Owner", 1)
	upsertTestIdentity(t, ctx, queries, "other", "Other", 1)
	verifier := &domainVerifierStub{addresses: []string{"2001:db8::10", "192.0.2.10"}}
	store, err := NewStore(db, "routes.test", StoreConfig{
		VerificationSuffix: "domains.routes.test",
		DomainVerifier:     verifier,
	})
	if err != nil {
		t.Fatal(err)
	}

	verification, err := store.CreateDomainVerification(ctx, "owner", "other.com", "first")
	if err != nil {
		t.Fatal(err)
	}
	if len(verification.Token) < 26 ||
		verification.VerificationTarget != verification.Token+".domains.routes.test" || !verification.Apex {
		t.Fatalf("verification = %#v", verification)
	}
	wantTypes := []string{"CNAME", "A", "AAAA", "CNAME"}
	if len(verification.Records) != len(wantTypes) {
		t.Fatalf("records = %#v", verification.Records)
	}
	for index, want := range wantTypes {
		if verification.Records[index].Type != want {
			t.Fatalf("record %d = %#v", index, verification.Records[index])
		}
	}

	verifier.err = errors.New("not propagated")
	if _, err := store.CompleteDomainVerification(ctx, "owner", verification.ID); !errors.Is(err, ErrDNSProofPending) {
		t.Fatalf("pending proof error = %v", err)
	}
	verifier.err = nil
	hostname, err := store.CompleteDomainVerification(ctx, "owner", verification.ID)
	if err != nil {
		t.Fatal(err)
	}
	if hostname.Hostname != "other.com" || hostname.Kind != HostnameKindCustomDomain || hostname.Status != HostnameStatusActive {
		t.Fatalf("custom hostname = %#v", hostname)
	}

	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Create(ctx, "owner", "a.b.c.d.e.f.g.h.other.com", "localhost:3000", "instance", routeToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, "owner", "x.a.b.c.d.e.f.g.h.other.com", "localhost:3001", "instance", routeToken, nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("ninth-level route error = %v", err)
	}

	transfer, err := store.CreateDomainVerification(ctx, "other", "other.com", "transfer")
	if err != nil {
		t.Fatal(err)
	}
	transferred, err := store.CompleteDomainVerification(ctx, "other", transfer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if transferred.ID != hostname.ID || transferred.IdentityID != "other" {
		t.Fatalf("transfer = %#v", transferred)
	}
	if routes, err := store.List(ctx, "owner"); err != nil || len(routes) != 0 {
		t.Fatalf("old owner routes = %#v, %v", routes, err)
	}
	if _, err := store.AuthenticateSession(ctx, created.Route.ID, created.Route.RouteVersion, created.SessionToken, "instance"); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("old owner session error = %v", err)
	}
	previous, err := store.GetDomainVerification(ctx, "owner", verification.ID)
	if err != nil || previous.Status != DomainVerificationStatusInvalidated {
		t.Fatalf("previous verification = %#v, %v", previous, err)
	}
}

func TestCoordinatorCustomDomainTransferDeactivatesRoutes(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	upsertTestIdentity(t, ctx, queries, "owner", "Owner", 1)
	upsertTestIdentity(t, ctx, queries, "other", "Other", 1)
	store, err := NewStore(db, "routes.test", StoreConfig{
		VerificationSuffix: "domains.routes.test",
		DomainVerifier:     &domainVerifierStub{addresses: []string{"192.0.2.10"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var removals []RouteRemovalReason
	coordinator, err := NewCoordinator(ctx, store, "instance", CoordinatorConfig{
		ObserveRouteRemoval: func(reason RouteRemovalReason) { removals = append(removals, reason) },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = coordinator.Close() })
	attachedWorker := &fakeWorker{limit: 1}
	if err := coordinator.AddWorker("local", attachedWorker); err != nil {
		t.Fatal(err)
	}

	verification, err := coordinator.CreateDomainVerification(ctx, "owner", "other.com", "owner-proof")
	if err != nil {
		t.Fatal(err)
	}
	hostname, err := coordinator.CompleteDomainVerification(ctx, "owner", verification.ID)
	if err != nil {
		t.Fatal(err)
	}
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	created, err := coordinator.Create(ctx, "owner", "app.other.com", "localhost:3000", routeToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinator.RegisterTransport(
		ctx, created.Route.ID, created.Route.RouteVersion, created.SessionToken,
		key.NewNode().Public().String(), "test",
	); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Ready(ctx, created.Route.ID, created.Route.RouteVersion, created.SessionToken); err != nil {
		t.Fatal(err)
	}
	if _, ok := coordinator.Lookup(created.Route.Hostname); !ok {
		t.Fatal("route was not published before transfer")
	}

	transfer, err := coordinator.CreateDomainVerification(ctx, "other", "other.com", "other-proof")
	if err != nil {
		t.Fatal(err)
	}
	transferred, err := coordinator.CompleteDomainVerification(ctx, "other", transfer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if transferred.ID != hostname.ID || transferred.IdentityID != "other" {
		t.Fatalf("transferred hostname = %#v", transferred)
	}
	if _, ok := coordinator.Lookup(created.Route.Hostname); ok {
		t.Fatal("previous owner's route remained published")
	}
	if len(attachedWorker.routes) != 1 || attachedWorker.routes[0].closed.Load() != 1 {
		t.Fatalf("previous owner's worker backend was not closed: %#v", attachedWorker.routes)
	}
	if len(removals) != 1 || removals[0] != RouteRemovalHostnameRemoved {
		t.Fatalf("route removals = %v", removals)
	}
	if _, err := coordinator.Heartbeat(
		ctx, created.Route.ID, created.Route.RouteVersion, created.SessionToken,
	); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("previous owner heartbeat error = %v", err)
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
	upsertTestIdentity(t, ctx, queries, "owner", "Owner", 1)
	upsertTestIdentity(t, ctx, queries, "other", "Other", 1)
	verifier := &domainVerifierStub{addresses: []string{"192.0.2.10"}}
	store, err := NewStore(db, "routes.test", StoreConfig{
		VerificationSuffix: "domains.routes.test", DomainVerifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	parent, err := store.CreateDomainVerification(ctx, "owner", "example.com", "parent")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompleteDomainVerification(ctx, "owner", parent.ID); err != nil {
		t.Fatal(err)
	}
	child, err := store.CreateDomainVerification(ctx, "other", "docs.example.com", "child")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompleteDomainVerification(ctx, "other", child.ID); !errors.Is(err, ErrNameUnavailable) {
		t.Fatalf("overlap error = %v", err)
	}
}

func TestVerifiedDomainVerificationsDoNotConsumePendingQuota(t *testing.T) {
	ctx := context.Background()
	db, err := state.Open(ctx, filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queries := statedb.New(db)
	upsertTestIdentity(t, ctx, queries, "owner", "Owner", 1)
	store, err := NewStore(db, "routes.test", StoreConfig{
		MaxActiveHostnames: 1, MaxHostnameRequests: 1,
		VerificationSuffix: "domains.routes.test", DomainVerifier: &domainVerifierStub{addresses: []string{"192.0.2.10"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.CreateDomainVerification(ctx, "owner", "first.com", "first")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CompleteDomainVerification(ctx, "owner", first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateDomainVerification(ctx, "owner", "second.com", "second"); err != nil {
		t.Fatalf("verification after verification: %v", err)
	}
}
