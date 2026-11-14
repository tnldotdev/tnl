package daemon

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationLocalHTTPServicePublicEndpoint(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	f := newServiceRuntimeFixture(t, false, nil)
	process := startSeparatedPrivateIngress(t, f, 0, "quic", nil)
	startSeparatedPrivateIngress(t, f, 1, "quic", nil)
	var posts atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts.Add(1)
			_, _ = io.Copy(w, r.Body)
			return
		}
		_, _ = io.WriteString(w, "local HTTP")
	}))
	t.Cleanup(target.Close)
	protocol := controlv1.ServiceProtocolHTTP
	binding := controlv1.ProjectServiceConfiguration{Protocol: &protocol, Target: "app", Public: new(true)}
	applied, err := f.identity.routes.ApplyProjectConfiguration(t.Context(), "local-exposure", controlv1.ApplyProjectConfigurationRequest{
		TeamId: f.identity.teamID, Source: &testProjectSource, Deployment: "local", ServiceDeclarations: controlv1.ProjectServiceDeclarations{"api": protocol},
		Configuration: controlv1.ProjectConfiguration{Services: map[string]controlv1.ProjectServiceConfiguration{"api": binding}, Webhooks: map[string]controlv1.ProjectWebhook{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var beforeRealization int
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*) FROM control.service_port_claims`).Scan(&beforeRealization); err != nil || beforeRealization != 0 {
		t.Fatal("local apply allocated a public endpoint before an app owner existed", beforeRealization, err)
	}
	request := controlv1.RealizeLocalProjectServiceRequest{
		TeamId: f.identity.teamID, SourceFingerprint: applied.SourceFingerprint, WorktreeKey: "checkout", Configuration: binding,
	}
	realized, err := f.identity.routes.RealizeLocalProjectService(t.Context(), "local-exposure", "api", request)
	if err != nil {
		t.Fatal(err)
	}
	service, err := f.identity.routes.GetService(t.Context(), realized.ServiceId)
	if err != nil || service.Endpoint == nil || !service.Endpoint.Public || service.Endpoint.Port < 1024 {
		t.Fatal("local HTTP has no allocated public endpoint", service, err)
	}
	stopPublisher := startPrivateHTTPPublisher(t, f, service, target.Listener.Addr().String())
	verification := f.visitorRoots.Clone()
	verification.ServerName = service.Endpoint.Hostname
	publicTransport := &http.Transport{TLSClientConfig: verification, ForceAttemptHTTP2: true, DialContext: workloadPublicEndpointDialer(t, process.ingresses[0].publicServices, service.Endpoint.Port)}
	t.Cleanup(publicTransport.CloseIdleConnections)
	publicClient := &http.Client{Transport: publicTransport, Timeout: 5 * time.Second}
	base := "https://" + net.JoinHostPort(service.Endpoint.Hostname, strconv.Itoa(service.Endpoint.Port))
	awaitServiceHTTPStatus(t, publicClient, base, "", "", http.StatusForbidden)
	token, err := f.identity.routes.CreateServiceHTTPGrant(t.Context(), service.Id, controlv1.CreateVisitorCredentialRequest{Kind: "token", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	awaitServiceHTTPStatus(t, publicClient, base, "Tnl-Visitor-Token", token.Permission.VisitorToken, http.StatusOK)
	person, err := f.identity.authority.IdentityContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	control, err := connectorstream.NewControl(f.identity.routes, f.identity.state, person.Identity.Id)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := f.identity.state.ListenService(t.Context(), person.Identity.Id, service.Id, "tcp")
	if err != nil {
		t.Fatal(err)
	}
	quic, tcp := f.connectors()
	local, stop := startRuntimeConnectorOn(t, f, service, listener, connectorstream.Config{Control: control, IdentityID: person.Identity.Id, RelayQUIC: quic, RelayTCP: tcp})
	defer stop()
	localTransport := &http.Transport{TLSClientConfig: verification.Clone(), ForceAttemptHTTP2: true}
	defer localTransport.CloseIdleConnections()
	localClient := &http.Client{Transport: localTransport, Timeout: 5 * time.Second}
	localBase := "https://" + local.Addr().String()
	checkPost := func(client *http.Client, base, credential, payload string) {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/once", strings.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		if credential != "" {
			r.Header.Set("Tnl-Visitor-Token", credential)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK || string(body) != payload || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
			t.Fatal("local service lost bytes, authorization, or verified TLS", response.StatusCode, string(body), err)
		}
	}
	checkPost(publicClient, base, token.Permission.VisitorToken, "public operation")
	checkPost(localClient, localBase, "", "connector operation")
	setPublic := func(public bool) {
		t.Helper()
		binding.Public = new(public)
		applied.Configuration.Services["api"] = binding
		updated, err := f.identity.routes.ApplyProjectConfiguration(t.Context(), "local-exposure", controlv1.ApplyProjectConfigurationRequest{
			TeamId: f.identity.teamID, Source: &testProjectSource, Deployment: "local", ExpectedRevision: applied.Revision, ServiceDeclarations: applied.ServiceDeclarations, Configuration: applied.Configuration,
		})
		if err != nil {
			t.Fatal(err)
		}
		applied = updated
		current, err := f.identity.routes.GetService(t.Context(), service.Id)
		if err != nil || current.TrustRevision != service.TrustRevision || current.Endpoint == nil || current.Endpoint.Hostname != service.Endpoint.Hostname || current.Endpoint.Port != service.Endpoint.Port || current.Endpoint.Public != public {
			t.Fatal("local exposure replaced an independently authorized binding", current, err)
		}
	}
	setPublic(false)
	publicTransport.CloseIdleConnections()
	if response, err := publicClient.Get(base + "/"); err == nil {
		_ = response.Body.Close()
		t.Fatal("cached public address bypassed current exposure")
	}
	checkPost(localClient, localBase, "", "private while public disabled")
	setPublic(true)
	awaitServiceHTTPStatus(t, publicClient, base, "Tnl-Visitor-Token", token.Permission.VisitorToken, http.StatusOK)
	checkPost(publicClient, base, token.Permission.VisitorToken, "public restored")
	port, found, err := f.identity.state.ServicePort(t.Context(), person.Identity.Id, service.Id)
	if err != nil || !found || net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) != local.Addr().String() {
		t.Fatal("exposure renumbered SQLite assignment", port, err)
	}
	var publicURLs int
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*) FROM control.public_urls`).Scan(&publicURLs); err != nil || publicURLs != 0 || posts.Load() != 4 {
		t.Fatal("local service created another publication or replayed a request", publicURLs, posts.Load(), err)
	}
	setPublic(false)
	stop()
	stopPublisher()
	released, err := f.identity.routes.ReleaseServiceEndpoint(t.Context(), service.Id, controlv1.ReleaseServiceEndpointRequest{
		ExpectedTrustRevision: service.TrustRevision, ExpectedPort: service.Endpoint.Port,
	})
	if err != nil || released.Endpoint == nil || released.Endpoint.Port != 0 || released.Endpoint.Hostname != service.Endpoint.Hostname {
		t.Fatal("release replaced the local TLS identity", released, err)
	}
	startPrivateHTTPPublisher(t, f, released, target.Listener.Addr().String())
	restarted, err := f.identity.state.ListenService(t.Context(), person.Identity.Id, service.Id, "tcp")
	if err != nil || restarted.Addr().String() != local.Addr().String() {
		t.Fatal("release changed the saved connector listener", restarted, err)
	}
	_, stopRestarted := startRuntimeConnectorOn(t, f, released, restarted, connectorstream.Config{Control: control, IdentityID: person.Identity.Id, RelayQUIC: quic, RelayTCP: tcp})
	defer stopRestarted()
	localTransport.CloseIdleConnections()
	checkPost(localClient, localBase, "", "private after reservation release")
	publicTransport.CloseIdleConnections()
	if response, err := publicClient.Get(base + "/"); err == nil {
		_ = response.Body.Close()
		t.Fatal("released public binding still admitted a visitor")
	}
	if posts.Load() != 5 {
		t.Fatal("release replayed application work", posts.Load())
	}
}

func TestIntegrationLocalHTTPServiceRequestLimitsAcrossPublicAndConnectorAccess(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	f := newServiceRuntimeFixture(t, false, nil)
	process := startSeparatedPrivateIngress(t, f, 0, "quic", nil)
	startSeparatedPrivateIngress(t, f, 1, "quic", nil)
	var requests atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, "limited local HTTP")
	}))
	t.Cleanup(target.Close)
	protocol := controlv1.ServiceProtocolHTTP
	realized, err := f.identity.routes.RealizeLocalProjectService(t.Context(), "local-http-limits", "api", controlv1.RealizeLocalProjectServiceRequest{
		TeamId: f.identity.teamID, SourceFingerprint: strings.Repeat("a", 64), WorktreeKey: "checkout",
		Configuration: controlv1.ProjectServiceConfiguration{
			Protocol: &protocol, Target: "app", Public: new(true),
			Http: &controlv1.ProjectServiceHTTP{Limits: &controlv1.ProjectHTTPApplicationLimits{Total: new(2)}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := f.identity.routes.GetService(t.Context(), realized.ServiceId)
	if err != nil || service.Endpoint == nil || !service.Endpoint.Public {
		t.Fatal("local HTTP endpoint was not realized", service, err)
	}
	person, err := f.identity.authority.IdentityContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	control, err := connectorstream.NewControl(f.identity.routes, f.identity.state, person.Identity.Id)
	if err != nil {
		t.Fatal(err)
	}
	quic, tcp := f.connectors()
	for round := range 2 {
		t.Run([]string{"first run", "publisher restart"}[round], func(t *testing.T) {
			stopPublisher := startPrivateHTTPPublisher(t, f, service, target.Listener.Addr().String())
			defer stopPublisher()
			verification := f.visitorRoots.Clone()
			verification.ServerName = service.Endpoint.Hostname
			publicTransport := &http.Transport{TLSClientConfig: verification, DialContext: workloadPublicEndpointDialer(t, process.ingresses[0].publicServices, service.Endpoint.Port)}
			defer publicTransport.CloseIdleConnections()
			publicClient := &http.Client{Transport: publicTransport, Timeout: 5 * time.Second}
			publicBase := "https://" + net.JoinHostPort(service.Endpoint.Hostname, strconv.Itoa(service.Endpoint.Port))
			// unauthorized readiness probes must not consume application budget.
			awaitServiceHTTPStatus(t, publicClient, publicBase, "", "", http.StatusForbidden)
			token, err := f.identity.routes.CreateServiceHTTPGrant(t.Context(), service.Id, controlv1.CreateVisitorCredentialRequest{Kind: "token", ExpiresAt: time.Now().Add(time.Hour)})
			if err != nil {
				t.Fatal(err)
			}
			listener, err := f.identity.state.ListenService(t.Context(), person.Identity.Id, service.Id, "tcp")
			if err != nil {
				t.Fatal(err)
			}
			local, stop := startRuntimeConnectorOn(t, f, service, listener, connectorstream.Config{Control: control, IdentityID: person.Identity.Id, RelayQUIC: quic, RelayTCP: tcp})
			defer stop()
			localTransport := &http.Transport{TLSClientConfig: verification.Clone()}
			defer localTransport.CloseIdleConnections()
			localClient := &http.Client{Transport: localTransport, Timeout: 5 * time.Second}
			request := func(client *http.Client, base, credential string, want int) {
				t.Helper()
				r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base, nil)
				if err != nil {
					t.Fatal(err)
				}
				if credential != "" {
					r.Header.Set("Tnl-Visitor-Token", credential)
				}
				response, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				body, readErr := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if readErr != nil || response.StatusCode != want {
					t.Fatal("local HTTP request budget not enforced", response.StatusCode, want, readErr)
				}
				if want == http.StatusServiceUnavailable && (string(body) != "HTTP request limit reached\n" || response.Header.Get("Retry-After") != "") {
					t.Fatal("HTTP request failed outside its configured total budget", string(body), response.Header.Get("Retry-After"))
				}
			}
			localBase := "https://" + local.Addr().String()
			request(publicClient, publicBase, token.Permission.VisitorToken, http.StatusOK)
			request(localClient, localBase, "", http.StatusOK)
			request(publicClient, publicBase, token.Permission.VisitorToken, http.StatusServiceUnavailable)
			request(localClient, localBase, "", http.StatusServiceUnavailable)
		})
	}
	if requests.Load() != 4 {
		t.Fatal("denied requests reached the target or restart lost its per-run budget", requests.Load())
	}
}
