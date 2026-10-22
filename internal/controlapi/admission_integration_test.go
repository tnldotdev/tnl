package controlapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityapi"
	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationDrainingControlAuthenticatedRenewalAndCleanup(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	dsn := testutil.NewDisposablePostgresDatabaseURL(t, "drain_authenticated")
	if err := controlstate.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, dsn, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	now := time.Now().UTC()
	session, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	m := session.Identity.Memberships[0]
	domains, err := d.ListTeamDomains(ctx, session.Identity.Identity.ID, m.TeamID)
	if err != nil {
		t.Fatal(err)
	}
	u, err := d.CreatePublicURL(ctx, controlstate.CreatePublicURLRequest{TeamID: m.TeamID, DomainID: domains[0].ID, MembershipID: m.ID, ActingIdentityID: session.Identity.Identity.ID, IdempotencyKey: "drain-url", RequestDigest: sha256.Sum256([]byte("drain-url")), CanonicalHostname: "drain." + m.ManagedLabel + ".example.test", Target: "http://127.0.0.1:3000", PublicURLScope: controlstate.PublicURLScopeMember, Purpose: controlstate.PublicURLPurposeApp, DNSState: controlstate.PublicURLDNSUnmanaged}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range []string{"drain-a", "drain-b"} {
		_, err := d.RegisterRelay(ctx, controlstate.RelayRegistration{RelayServiceID: service, RelayID: service, RelayRunID: "run-" + service, ProtocolVersion: 1, RelayAddress: service + ".example.test:443", TLSServerName: service + ".example.test", InternalRelayAddress: service + ".internal:9443", InternalNetworks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}, ConnectionCapacity: 10, StreamCapacity: 100}, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
	}
	var draining atomic.Bool
	h, err := NewHandler(Config{DNSAutomation: true, AcceptingNewWork: func() bool { return !draining.Load() }}, d, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	t.Cleanup(server.Close)
	if _, err := authorityapi.Register(h, authorityapi.Config{ControlURL: server.URL}, d); err != nil {
		t.Fatal(err)
	}
	owner, err := controlclient.New(server.URL, server.Client(), session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	client, err := controlclient.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := authorityclient.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	enroll := func(request controlv1.CreatePublisherEnrollmentRequest) (string, ed25519.PrivateKey) {
		t.Helper()
		e, err := owner.CreatePublisherEnrollment(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		p, err := authority.RedeemPublisherEnrollment(ctx, e.EnrollmentKey, public)
		if err != nil {
			t.Fatal(err)
		}
		access, err := authority.ExchangePublisherAssertion(ctx, p.ClientId, p.GrantId, p.KeyId, private)
		if err != nil {
			t.Fatal(err)
		}
		return access, private
	}
	access, private := enroll(controlv1.CreatePublisherEnrollmentRequest{TeamId: m.TeamID, Name: "drain-public", Kind: "installed", PublicUrlId: &u.ID})
	proof, err := publisheridentity.SignRun(private, u.ID, "drain-run")
	if err != nil {
		t.Fatal(err)
	}
	publicRun, err := client.CreatePublisherRun(ctx, u.ID, "drain-run", access, proof)
	if err != nil {
		t.Fatal(err)
	}
	service, err := owner.CreatePrivateService(ctx, m.TeamID, "drain-db", "drain-db", controlv1.PrivateServiceMetadata{Protocol: controlv1.Postgres, TrustRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	managedAccess, _ := enroll(controlv1.CreatePublisherEnrollmentRequest{TeamId: m.TeamID, Name: "drain-private", Kind: "installed", PrivateServiceId: &service.Id})
	prepared, err := client.PreparePrivateServiceRun(ctx, service.Id, "drain-private", managedAccess, controlv1.PrivateServiceRunDeclaration{Protocol: controlv1.Postgres, TrustRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	managedRun, err := client.StartManagedServiceRun(ctx, service.Id, prepared.PrivateRunId, managedAccess, prepared.RunNumber)
	if err != nil {
		t.Fatal(err)
	}
	draining.Store(true)
	if _, err := client.CreatePublisherRun(ctx, u.ID, "drain-run", access, proof); !errors.Is(err, controlclient.ErrUnavailable) {
		t.Fatal("drain admitted public run", err)
	}
	if _, err := client.PreparePrivateServiceRun(ctx, service.Id, "drain-private", managedAccess, controlv1.PrivateServiceRunDeclaration{Protocol: controlv1.Postgres, TrustRevision: 1}); !errors.Is(err, controlclient.ErrUnavailable) {
		t.Fatal("drain admitted managed preparation", err)
	}
	if _, err := client.StartManagedServiceRun(ctx, service.Id, prepared.PrivateRunId, managedAccess, prepared.RunNumber); !errors.Is(err, controlclient.ErrUnavailable) {
		t.Fatal("drain admitted managed start", err)
	}
	publicToken := credentials.PublishRunToken(publicRun.PublishRunToken)
	if _, err := client.HeartbeatPublishRun(ctx, publicRun.PublishRun.Id, uint64(publicRun.PublishRun.PublishRunNumber), publicToken); err != nil {
		t.Fatal("drain blocked authenticated public renewal", err)
	}
	managedToken := credentials.ManagedRunToken(managedRun.RunToken)
	if _, err := client.HeartbeatPrivateServiceRun(ctx, service.Id, prepared.PrivateRunId, managedToken); err != nil {
		t.Fatal("drain blocked authenticated managed renewal", err)
	}
	if err := client.ClosePublishRun(ctx, publicRun.PublishRun.Id, publicToken); err != nil {
		t.Fatal("drain blocked authenticated public cleanup", err)
	}
	if err := client.ClosePrivateServiceRun(ctx, service.Id, prepared.PrivateRunId, managedToken); err != nil {
		t.Fatal("drain blocked authenticated managed cleanup", err)
	}
}
