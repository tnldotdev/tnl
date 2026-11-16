package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
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
			"web": {Target: target.URL, Protocol: &protocol, PublicUrl: &controlv1.ProjectServicePublicURL{Access: &controlv1.ProjectPublicAccess{Mode: &mode}}},
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
		service := "web"
		var allocation *controlv1.AllocateEphemeralPublicURLRequest
		if temporary {
			service = ""
			invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
			if err != nil {
				t.Fatal(err)
			}
			allocation = &controlv1.AllocateEphemeralPublicURLRequest{InvocationId: invocation, Target: target.URL, AccessMode: &mode}
		}
		native, selected, err := publisheridentity.PrepareDeployment(t.Context(), f.identity.routes, f.identity.authority, approval, private, "production", service, allocation)
		if err != nil {
			t.Fatal(err)
		}
		u := selected.PublicUrl
		quic, tcp := f.connectors()
		config := f.identity.publisherConfig(target.URL, quic, tcp)
		config.Control, config.Identity, config.Audit = native, native, native
		config.VisitorControl, config.BrowserControl, config.Shares = native, native, native
		config.Hostname, config.DomainID, config.MembershipID = u.CanonicalHostname, u.DomainId, ""
		config.PublicURLScope, config.PolicyRevision = u.PublicUrlScope, uint64(u.PolicyRevision)
		config.Ephemeral, config.AssignedPublicURL = temporary, &u
		handle := startOwnedIntegrationPublisher(t, f.owner, config, nil)
		ready := waitForPublisherReady(t, handle)
		waitForReadyPublisherConnections(t, f.inspect, ready.PublicURLID, ready.PublishRunNumber, 2)
		waitForIngressRoutingCurrent(t, f.inspect, 1)
		response, body, err := f.visitor.requestURL(http.MethodGet, ready.PublicURL, nil)
		if err != nil || response.StatusCode != http.StatusOK || string(body) != "deployment visitor" {
			t.Fatal("authorized deployment publication did not carry visitor traffic", err)
		}
		f.visitor.transport.CloseIdleConnections()
		stopIntegrationPublisher(t, handle)
		// the allocation owner deletes its exact URL after joining the run;
		// publisher.Run never adopts an already allocated URL's lifetime.
		if temporary {
			if err := native.DeletePublicURL(t.Context(), u.Id); err != nil {
				t.Fatal(err)
			}
		}
		var state string
		if err := f.inspect.QueryRowContext(t.Context(), `SELECT lifecycle_state FROM control.public_urls WHERE id=$1`, u.Id).Scan(&state); err != nil {
			t.Fatal(err)
		}
		if temporary && state != "deleted" || !temporary && state != "enabled" {
			t.Fatal("publication cleanup changed the wrong URL lifetime", state)
		}
	}
}
