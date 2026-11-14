package public

import (
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationServiceEndpointReleaseHTTPContract(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	url := testutil.NewDisposablePostgresDatabaseURL(t, "service_endpoint_release_http")
	if err := controlstate.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, url, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeSimple)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	if err := d.ConfigureIngressServicePorts(ctx, controlstate.PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25443}}); err != nil {
		t.Fatal(err)
	}
	session, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(Config{ControlURL: "https://control.example.test", ManagedURLMode: naming.ManagedURLModeSimple}, DatabaseStores(d), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(h)
	t.Cleanup(server.Close)
	owner, err := clientcontrol.New(server.URL, server.Client(), session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	anonymous, err := clientcontrol.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := owner.ResolveProjectSource(ctx, testProjectSource)
	if err != nil {
		t.Fatal(err)
	}
	protocol := controlv1.ServiceProtocolHTTP
	body := controlv1.ApplyProjectConfigurationRequest{Deployment: "production", TeamId: session.Identity.Memberships[0].TeamID, Source: &testProjectSource,
		ServiceDeclarations: controlv1.ProjectServiceDeclarations{"api": protocol},
		Configuration:       controlv1.ProjectConfiguration{Settings: &controlv1.DeploymentSettings{}, Services: map[string]controlv1.ProjectServiceConfiguration{"api": {Target: "http://localhost:3000", Public: new(true)}}, Webhooks: map[string]controlv1.ProjectWebhook{}}}
	applied, err := owner.ApplyProjectConfiguration(ctx, resolved.ProjectKey, body)
	if err != nil {
		t.Fatal(err)
	}
	id := *applied.Services[0].ServiceId
	saved, err := owner.GetService(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	request := controlv1.ReleaseServiceEndpointRequest{ExpectedTrustRevision: saved.TrustRevision, ExpectedPort: saved.Endpoint.Port}
	if _, err := anonymous.ReleaseServiceEndpoint(ctx, id, request); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("anonymous release", err)
	}
	if _, err := owner.ReleaseServiceEndpoint(ctx, id, request); !errors.Is(err, clientcontrol.ErrStatusConflict) {
		t.Fatal("enabled release", err)
	}
	body.ExpectedRevision = applied.Revision
	binding := body.Configuration.Services["api"]
	binding.Public = new(false)
	body.Configuration.Services["api"] = binding
	if _, err := owner.ApplyProjectConfiguration(ctx, resolved.ProjectKey, body); err != nil {
		t.Fatal(err)
	}
	released, err := owner.ReleaseServiceEndpoint(ctx, id, request)
	if err != nil || released.Id != id || released.Endpoint.Port != 0 || released.Endpoint.Hostname != saved.Endpoint.Hostname || released.TrustRevision != saved.TrustRevision+1 {
		t.Fatal("native release roundtrip changed surviving identity", released, err)
	}
	if _, err := owner.ReleaseServiceEndpoint(ctx, id, request); !errors.Is(err, clientcontrol.ErrStatusConflict) {
		t.Fatal("stale release request", err)
	}
}
