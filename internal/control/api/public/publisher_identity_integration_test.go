package public

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationPublisherIdentityHTTPContract(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, test := range []struct {
		name      string
		selection *trafficlimits.Selection
	}{
		{name: "defaults"},
		{name: "explicit", selection: &trafficlimits.Selection{Connections: new(48)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			testPublisherIdentityHTTPContract(t, test.selection)
		})
	}
}

func testPublisherIdentityHTTPContract(t *testing.T, selection *trafficlimits.Selection) {
	t.Helper()
	url := testutil.NewDisposablePostgresDatabaseURL(t, "publisher_http")
	if err := controlstate.Migrate(t.Context(), url); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(t.Context(), url, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeGenerated)
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
	service, err := d.CreateServiceAt(t.Context(), m.TeamID, session.Identity.Identity.ID, "app", "app", controlstate.ServicePlacement{}, now, controlstate.ServiceMetadata{Protocol: "http"},
		&controlstate.ProjectServiceConfiguration{Target: "http://127.0.0.1:3000", Public: new(true)})
	if err != nil {
		t.Fatal(err)
	}
	control, err := NewHandler(Config{DNSAutomation: true}, DatabaseStores(d), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(control)
	t.Cleanup(server.Close)
	if _, err := controlauthority.Register(control, controlauthority.Config{ControlURL: server.URL}, d); err != nil {
		t.Fatal(err)
	}
	owner, err := clientcontrol.New(server.URL, server.Client(), session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	client, err := clientcontrol.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	e, err := owner.CreatePublisherEnrollment(t.Context(), controlv1.CreatePublisherEnrollmentRequest{TeamId: m.TeamID, Name: "http-client", Kind: "installed", ServiceId: &service.ID})
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
	read, err := client.GetPublisherService(t.Context(), service.ID, access)
	if err != nil || read.Id != service.ID {
		t.Fatalf("scoped service read = %+v, %v", read, err)
	}
	for _, service := range []string{"http-a", "http-b"} {
		_, err := d.RegisterRelay(t.Context(), controlstate.RelayRegistration{RelayServiceID: service, RelayID: service, RelayRunID: "run-" + service, ProtocolVersion: 1, RelayAddress: service + ".example.test:443", TLSServerName: service + ".example.test", InternalRelayAddress: service + ".internal:9443", InternalNetworks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}, ConnectionCapacity: 10, StreamCapacity: 100}, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
	}
	declaration := controlv1.ServiceRunDeclaration{Protocol: controlv1.ServiceProtocolHTTP, TrustRevision: service.TrustRevision}
	if selection != nil {
		declaration.Traffic = &controlv1.TrafficSelection{Connections: selection.Connections}
	}
	prepared, err := client.PrepareServiceRun(t.Context(), service.ID, "http-run", access, declaration)
	if err != nil {
		t.Fatal(err)
	}
	wantConnections := trafficlimits.Default().Connections
	if selection != nil {
		wantConnections = *selection.Connections
	}
	if prepared.Traffic.Connections != wantConnections {
		t.Fatalf("HTTP run traffic = %+v, want %d connections", prepared.Traffic, wantConnections)
	}
	retry, err := client.PrepareServiceRun(t.Context(), service.ID, "http-run", access, declaration)
	if err != nil || retry.ServiceRunId != prepared.ServiceRunId || !reflect.DeepEqual(retry.Traffic, prepared.Traffic) {
		t.Fatalf("HTTP run retry changed credentials: %v", err)
	}
	changed := declaration
	changed.Traffic = &controlv1.TrafficSelection{Connections: new(24)}
	if _, err := client.PrepareServiceRun(t.Context(), service.ID, "http-run", access, changed); !errors.Is(err, clientcontrol.ErrStatusConflict) {
		t.Fatalf("HTTP run retry changed traffic selection: %v", err)
	}
	setup, err := client.StartServiceRun(t.Context(), service.ID, prepared.ServiceRunId, access, prepared.RunNumber)
	if err != nil {
		t.Fatal(err)
	}
	startRetry, err := client.StartServiceRun(t.Context(), service.ID, prepared.ServiceRunId, access, prepared.RunNumber)
	if err != nil || startRetry.RunToken != setup.RunToken || !reflect.DeepEqual(startRetry.PublisherConnections, setup.PublisherConnections) {
		t.Fatal("start retry changed credentials", err)
	}
	if _, err := client.StartServiceRun(t.Context(), service.ID, prepared.ServiceRunId, access, prepared.RunNumber+1); !errors.Is(err, clientcontrol.ErrNotFound) {
		t.Fatalf("HTTP run start crossed run numbers: %v", err)
	}
	other, err := d.CreateServiceAt(t.Context(), m.TeamID, session.Identity.Identity.ID, "other", "other", controlstate.ServicePlacement{}, now, controlstate.ServiceMetadata{Protocol: "http"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.PrepareServiceRun(t.Context(), other.ID, "http-run", access, declaration); !errors.Is(err, clientcontrol.ErrNotFound) {
		t.Fatalf("HTTP publisher grant crossed services: %v", err)
	}
	if _, err := client.StartServiceRun(t.Context(), other.ID, prepared.ServiceRunId, access, prepared.RunNumber); !errors.Is(err, clientcontrol.ErrNotFound) {
		t.Fatalf("HTTP prepared run crossed services: %v", err)
	}
	if _, err := client.PrepareServiceRun(t.Context(), service.ID, "http-run", session.AccessToken.String(), declaration); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatalf("control session bypassed identity authentication: %v", err)
	}
	// a publisher token cannot become a control session or change saved policy.
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/v1/services?team_id="+m.TeamID, nil)
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
	if _, err := authority.ExchangePublisherAssertion(t.Context(), p.ClientId, p.GrantId, p.KeyId, private); !errors.Is(err, clientauthority.ErrUnauthenticated) {
		t.Fatalf("retired key accepted over HTTP: %v", err)
	}
	if _, err := authority.ExchangePublisherAssertion(t.Context(), p.ClientId, p.GrantId, replacement, newPrivate); err != nil {
		t.Fatal(err)
	}
	if _, err := client.StartServiceRun(t.Context(), service.ID, prepared.ServiceRunId, access, prepared.RunNumber); err != nil {
		t.Fatalf("rotation broke a retry with the still-valid issued token: %v", err)
	}
	// signatures include the selected grant; exchanging one for another fails.
	assertion, _ := publisherproof.Sign(p.ClientId, replacement, "other-grant", server.URL+"/v1/publisher-token", newPrivate, time.Now())
	if _, err := d.ExchangePublisherAssertion(t.Context(), p.ClientId, p.GrantId, server.URL+"/v1/publisher-token", assertion, "", time.Now()); !errors.Is(err, controlstate.ErrPublisherIdentity) {
		t.Fatalf("assertion changed grant during exchange: %v", err)
	}
	if err := owner.RevokePublisherGrant(t.Context(), m.TeamID, p.ClientId, p.GrantId); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetPublisherService(t.Context(), service.ID, access); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatalf("revoked token accepted over HTTP: %v", err)
	}
	if _, err := client.HeartbeatServiceRun(t.Context(), service.ID, setup.ServiceRunId, credentials.ServiceRunToken(setup.RunToken), controlv1.ServiceRunHeartbeat{Healthy: true, StreamCapacity: 64}); !errors.Is(err, clientcontrol.ErrNotFound) {
		t.Fatalf("revoked grant kept a live HTTP run: %v", err)
	}
}
