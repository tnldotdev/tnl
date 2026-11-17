package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationDeploymentPublicationRealControlAndVisitor(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	f := newSplitPublishFixture(t, "deployment-publication")
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "deployment visitor")
	}))
	cleanupIntegrationHTTPServer(t, target, f.owner)
	mode, protocol := controlv1.Anonymous, controlv1.ServiceProtocol("http")
	applied, err := f.identity.routes.ApplyProjectConfiguration(t.Context(), "publication", controlv1.ApplyProjectConfigurationRequest{
		TeamId: f.identity.teamID, Source: &testProjectSource, Deployment: "production",
		ServiceDeclarations: controlv1.ProjectServiceDeclarations{"web": protocol},
		Configuration: controlv1.ProjectConfiguration{Settings: &controlv1.DeploymentSettings{}, Services: map[string]controlv1.ProjectServiceConfiguration{
			"web": {Target: target.URL, Protocol: &protocol, Public: new(true), Http: &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectHTTPAccess{Mode: &mode}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if applied.Deployments == nil || len(*applied.Deployments) != 1 {
		t.Fatal("apply did not return the saved deployment")
	}
	registration := controlv1.RegisterDeploymentCredentialRequest{Name: "application", PublicKey: base64.RawURLEncoding.EncodeToString(public), ExpiresIn: 600, DeploymentIds: new([]string{(*applied.Deployments)[0].Id})}
	registration.Permissions.Publish = &controlv1.DeploymentPublishSelection{Services: new(controlv1.DeploymentCredentialServiceSelection{"web"}), Temporary: new(controlv1.TemporaryPublicationAnonymous)}
	approval, err := f.identity.routes.RegisterDeploymentCredential(t.Context(), f.identity.teamID, "publication", "publication", registration)
	if err != nil {
		t.Fatal(err)
	}
	for _, temporary := range []bool{false, true} {
		var native *publisheridentity.Native
		var selected *controlv1.Service
		if temporary {
			var invocation string
			invocation, err = opaqueid.New(opaqueid.InvocationPrefix)
			if err != nil {
				t.Fatal(err)
			}
			native, err = publisheridentity.NewDeploymentAllocator(f.identity.routes, f.identity.authority, approval, private, "production")
			if err != nil {
				t.Fatal(err)
			}
			var service controlv1.Service
			service, err = native.AllocateService(t.Context(), controlv1.AllocateServiceRequest{InvocationId: invocation, Configuration: controlv1.ProjectServiceConfiguration{
				Protocol: &protocol, Target: target.URL, Public: new(true),
				Http: &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectHTTPAccess{Mode: &mode}},
			}})
			selected = &service
		} else {
			native, selected, err = publisheridentity.PrepareDeployment(t.Context(), f.identity.routes, f.identity.authority, approval, private, "production", "web")
		}
		if err != nil {
			t.Fatal(err)
		}
		quic, tcp := f.connectors()
		config := publisherservice.RunConfig{
			Control: native, Access: native.Access, State: f.identity.state, ServiceID: selected.Id,
			PublisherIdentityID: approval.ClientId, PublisherGrantID: approval.GrantId, PublisherKeyID: approval.KeyId,
			Metadata: publisheridentity.ServiceMetadata(*selected), Target: strings.TrimPrefix(target.URL, "http://"),
			RelayQUIC: quic, RelayWebSocket: tcp, HeartbeatInterval: 100 * time.Millisecond, DrainTime: time.Second,
		}
		handle := startOwnedIntegrationPublisher(t, f.owner, config, nil)
		ready := waitForPublisherReady(t, handle)
		waitForReadyPublisherConnections(t, f.inspect, ready.ServiceId, ready.RunNumber, 2)
		waitForIngressRoutingCurrent(t, f.inspect, 1)
		response, body, err := f.visitor.requestURL(http.MethodGet, serviceHTTPAddress(ready), nil)
		if err != nil || response.StatusCode != http.StatusOK || string(body) != "deployment visitor" {
			t.Fatal("authorized deployment publication did not carry visitor traffic", err)
		}
		f.visitor.transport.CloseIdleConnections()
		stopIntegrationPublisher(t, handle)
		// the allocation owner deletes its exact service after joining the run;
		// the service run never adopts the saved service's lifetime.
		if temporary {
			if err := native.DeleteAllocatedService(t.Context(), selected.Id); err != nil {
				t.Fatal(err)
			}
		}
		var deleted, enabled bool
		if err := f.inspect.QueryRowContext(t.Context(), `SELECT deleted_at IS NOT NULL, enabled FROM control.services WHERE id=$1`, selected.Id).Scan(&deleted, &enabled); err != nil {
			t.Fatal(err)
		}
		if deleted != temporary || !temporary && !enabled {
			t.Fatal("publication cleanup changed the wrong service lifetime", deleted, enabled)
		}
	}
}
