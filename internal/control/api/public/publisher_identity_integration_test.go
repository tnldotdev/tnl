package controlapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	authorityclient "github.com/tnldotdev/tnl/internal/client/authority"
	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	authorityapi "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	publisheridentity "github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationPublisherIdentityHTTPContract(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	url := testutil.NewDisposablePostgresDatabaseURL(t, "publisher_http")
	if err := controlstate.Migrate(t.Context(), url); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(t.Context(), url, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	now := time.Now().UTC()
	session, err := controltest.Session(t.Context(), d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	m := session.Identity.Memberships[0]
	domains, err := d.ListTeamDomains(t.Context(), session.Identity.Identity.ID, m.TeamID)
	if err != nil {
		t.Fatal(err)
	}
	u, err := d.CreatePublicURL(t.Context(), controlstate.CreatePublicURLRequest{TeamID: m.TeamID, DomainID: domains[0].ID, MembershipID: m.ID, ActingIdentityID: session.Identity.Identity.ID, IdempotencyKey: "url", RequestDigest: sha256.Sum256([]byte("url")), CanonicalHostname: "app." + m.ManagedLabel + ".example.test", Target: "http://127.0.0.1:3000", PublicURLScope: controlstate.PublicURLScopeMember, Purpose: controlstate.PublicURLPurposeApp, DNSState: controlstate.PublicURLDNSUnmanaged}, now)
	if err != nil {
		t.Fatal(err)
	}
	control, err := NewHandler(Config{DNSAutomation: true}, d, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(control)
	t.Cleanup(server.Close)
	if _, err := authorityapi.Register(control, authorityapi.Config{ControlURL: server.URL}, d); err != nil {
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
	e, err := owner.CreatePublisherEnrollment(t.Context(), controlv1.CreatePublisherEnrollmentRequest{TeamId: m.TeamID, Name: "http-client", Kind: "installed", PublicUrlId: &u.ID})
	if err != nil {
		t.Fatal(err)
	}
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	p, err := authority.RedeemPublisherEnrollment(t.Context(), e.EnrollmentKey, public)
	if err != nil {
		t.Fatal(err)
	}
	access, err := authority.ExchangePublisherAssertion(t.Context(), p.ClientId, p.GrantId, p.KeyId, private)
	if err != nil {
		t.Fatal(err)
	}
	read, err := client.PublisherPublicURL(t.Context(), access)
	if err != nil || read.Id != u.ID {
		t.Fatalf("scoped URL read = %+v, %v", read, err)
	}
	for _, service := range []string{"http-a", "http-b"} {
		_, err := d.RegisterRelay(t.Context(), controlstate.RelayRegistration{RelayServiceID: service, RelayID: service, RelayRunID: "run-" + service, ProtocolVersion: 1, RelayAddress: service + ".example.test:443", TLSServerName: service + ".example.test", InternalRelayAddress: service + ".internal:9443", InternalNetworks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}, ConnectionCapacity: 10, StreamCapacity: 100}, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
	}
	proof, err := publisheridentity.SignRun(private, u.ID, "http-run")
	if err != nil {
		t.Fatal(err)
	}
	setup, err := client.CreatePublisherRun(t.Context(), u.ID, "http-run", access, proof)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := client.CreatePublisherRun(t.Context(), u.ID, "http-run", access, proof)
	if err != nil || retry.PublishRun.Id != setup.PublishRun.Id || retry.PublishRunToken != setup.PublishRunToken {
		t.Fatalf("HTTP run retry changed credentials: %v", err)
	}
	wrongProof, _ := publisheridentity.SignRun(private, u.ID, "other-attempt")
	if _, err := client.CreatePublisherRun(t.Context(), u.ID, "http-run", access, wrongProof); !errors.Is(err, controlclient.ErrUnauthenticated) {
		t.Fatalf("HTTP run proof crossed attempts: %v", err)
	}
	if _, err := client.CreatePublisherRun(t.Context(), u.ID, "http-run", session.AccessToken.String(), proof); !errors.Is(err, controlclient.ErrUnauthenticated) {
		t.Fatalf("control session bypassed identity authentication: %v", err)
	}
	// a publisher token cannot become a control session or change saved policy.
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/v1/public-urls?team_id="+m.TeamID, nil)
	request.Header.Set("Authorization", "Bearer "+access)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatalf("publisher token authorized team reads: %d", response.StatusCode)
	}
	_, newPrivate, _ := ed25519.GenerateKey(rand.Reader)
	replacement, _ := opaqueid.New(opaqueid.PublisherIdentityKeyPrefix)
	if err := authority.RotatePublisherKey(t.Context(), access, p.ClientId, p.GrantId, p.KeyId, replacement, private, newPrivate); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.ExchangePublisherAssertion(t.Context(), p.ClientId, p.GrantId, p.KeyId, private); !errors.Is(err, authorityclient.ErrUnauthenticated) {
		t.Fatalf("retired key accepted over HTTP: %v", err)
	}
	if _, err := authority.ExchangePublisherAssertion(t.Context(), p.ClientId, p.GrantId, replacement, newPrivate); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreatePublisherRun(t.Context(), u.ID, "http-run", access, proof); err != nil {
		t.Fatalf("rotation broke a retry with the still-valid issued token: %v", err)
	}
	// signatures include the selected grant; exchanging one for another fails.
	assertion, _ := publisheridentity.Sign(p.ClientId, replacement, "other-grant", server.URL+"/v1/publisher-token", newPrivate, time.Now())
	if _, err := d.ExchangePublisherAssertion(t.Context(), p.ClientId, p.GrantId, server.URL+"/v1/publisher-token", assertion, "", time.Now()); !errors.Is(err, controlstate.ErrPublisherIdentity) {
		t.Fatalf("assertion changed grant during exchange: %v", err)
	}
	if err := owner.RevokePublisherGrant(t.Context(), m.TeamID, p.ClientId, p.GrantId); err != nil {
		t.Fatal(err)
	}
	if _, err := client.PublisherPublicURL(t.Context(), access); !errors.Is(err, controlclient.ErrUnauthenticated) {
		t.Fatalf("revoked token accepted over HTTP: %v", err)
	}
	if _, err := client.HeartbeatPublishRun(t.Context(), setup.PublishRun.Id, uint64(setup.PublishRun.PublishRunNumber), credentials.PublishRunToken(setup.PublishRunToken)); !errors.Is(err, controlclient.ErrUnauthenticated) {
		t.Fatalf("revoked grant kept a live HTTP run: %v", err)
	}
}
