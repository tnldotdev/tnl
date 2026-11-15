package daemon

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/publisher/integrations"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationOAuthRoutesToOriginatingService(t *testing.T) {
	fixture := newStandalonePublishFixture(t, "oauth-routing")
	state, err := clientstate.OpenWithOptions(t.Context(), fixture.owner.directory+"/state", clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	server, oauthHost := fixture.identity.controlOrigin, fixture.identity.hostname
	quic, tcp := fixture.connectors()
	oauthService, oauth := fixture.identity.prepareService(t, "", quic, tcp, controlv1.ProjectServiceConfiguration{})
	oauth.Handler = integrations.OAuthHandler(state, server, oauthHost, nil)
	oauthPublisher := startOwnedIntegrationPublisher(t, fixture.owner, oauth, fixture.diagnostics)
	oauthReady := waitForPublisherReady(t, oauthPublisher)
	waitForReadyPublisherConnections(t, fixture.inspect, oauthReady.ServiceId, oauthReady.RunNumber, 2)
	project := t.TempDir()
	_, namespace, found := strings.Cut(oauthHost, ".")
	if !found || namespace == "" {
		t.Fatalf("OAuth callback hostname has no namespace: %q", oauthHost)
	}
	integrationScope := clientstate.IntegrationScope{PrimaryProjectRoot: project, Namespace: namespace}
	type app struct {
		name, hostname string
		callbacks      chan string
		tunnel         *clientstate.Tunnel
	}
	apps := make([]app, 0, 2)
	for _, name := range []string{"web", "api"} {
		hostname := name + strings.TrimPrefix(oauthHost, "oauth-routing")
		observed := make(chan string, 2)
		target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			switch request.URL.Path {
			case "/login":
				response.Header().Set("Set-Cookie", "session="+name+"; Secure; HttpOnly; SameSite=Lax; Path=/")
				provider := url.URL{Scheme: "https", Host: "idp.example.test", Path: "/authorize"}
				query := provider.Query()
				query.Set("state", name+"-state")
				query.Set("redirect_uri", "https://"+oauthHost+"/api/auth/callback/provider")
				provider.RawQuery = query.Encode()
				response.Header().Set("Location", provider.String())
				response.WriteHeader(http.StatusFound)
			case "/api/auth/callback/provider":
				observed <- request.URL.RawQuery + " " + request.Header.Get("Cookie")
				response.WriteHeader(http.StatusNoContent)
			default:
				http.NotFound(response, request)
			}
		}))
		t.Cleanup(target.Close)
		saved, config := fixture.identity.prepareService(t, target.URL, quic, tcp, controlv1.ProjectServiceConfiguration{Hostname: &hostname})
		tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
			Command: clientstate.TunnelCommandPublish, Server: server, Project: project,
			Service: name, ServiceID: saved.Id, ServiceProtocol: "http", Target: target.URL, IntegrationScope: integrationScope,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tunnel.Finish(context.Background(), nil) })
		observe := integrations.Observer(state, server, oauthHost, integrationScope, tunnel.ID())
		config.HTTPResponseHooks = func(run publisherservice.HTTPRun) httpstream.ResponseHooks {
			return httpstream.ResponseHooks{Observe: func(response *http.Response) error { return observe(response, run) }}
		}
		var binding controlv1.ServiceRunPreparation
		config.Prepared = func(run controlv1.ServiceRunPreparation) error {
			binding = run
			return tunnel.SetProvisioning(t.Context(), uint64(run.RunNumber))
		}
		config.Ready = func() error {
			return tunnel.SetReady(t.Context(), serviceHTTPAddress(binding), uint64(binding.RunNumber))
		}
		handle := startOwnedIntegrationPublisher(t, fixture.owner, config, fixture.diagnostics)
		ready := waitForPublisherReady(t, handle)
		waitForReadyPublisherConnections(t, fixture.inspect, ready.ServiceId, ready.RunNumber, 2)
		apps = append(apps, app{name: name, hostname: hostname, callbacks: observed, tunnel: tunnel})
	}
	waitForIngressRoutingCurrent(t, fixture.inspect, 1)
	if err := state.MarkIntegrationURLReady(t.Context(), server, oauthHost, "test-publisher", oauthReady.ServiceId, uint64(oauthReady.RunNumber)); err != nil {
		t.Fatal(err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	visitor := *fixture.visitor.client
	visitor.Jar = jar
	visitor.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	visit := func(address string) *http.Response {
		t.Helper()
		response, err := visitor.Get(address)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, response.Body); err != nil {
			t.Fatal(err)
		}
		if err := response.Body.Close(); err != nil {
			t.Fatal(err)
		}
		return response
	}
	for _, app := range apps {
		authorization := visit("https://" + app.hostname + "/login")
		if authorization.StatusCode != http.StatusFound || !strings.Contains(authorization.Header.Get("Location"), "state="+app.name+"-state") {
			t.Fatalf("%s authorization = %d %q", app.name, authorization.StatusCode, authorization.Header.Get("Location"))
		}
	}
	// a new handler-backed run must load the same targetless URL and retain the
	// callback state recorded before the publisher stopped.
	stopIntegrationPublisher(t, oauthPublisher)
	oauthPublisher = startOwnedIntegrationPublisher(t, fixture.owner, oauth, fixture.diagnostics)
	restarted := fixture.waitReady(t, oauthPublisher)
	if restarted.ServiceId != oauthReady.ServiceId || restarted.ServiceRunId == oauthReady.ServiceRunId || restarted.RunNumber <= oauthReady.RunNumber {
		t.Fatalf("OAuth restart replaced saved URL or reused a run: %+v -> %+v", oauthReady, restarted)
	}
	saved, err := fixture.identity.routes.GetService(t.Context(), oauthService.Id)
	declaration, _, declarationErr := fixture.identity.routes.GetServiceConfiguration(t.Context(), oauthService.Id)
	if err != nil || declarationErr != nil || declaration == nil || declaration.Target != "app" || saved.Ephemeral || saved.Endpoint == nil || saved.Endpoint.Hostname != oauthHost {
		t.Fatalf("OAuth reload = %+v, %v", saved, err)
	}
	if err := state.MarkIntegrationURLReady(t.Context(), server, oauthHost, "test-publisher", restarted.ServiceId, uint64(restarted.RunNumber)); err != nil {
		t.Fatal(err)
	}
	// return callbacks in the opposite order: the shared hostname must use the
	// observed state, not the currently active service or the latest login.
	for index := len(apps) - 1; index >= 0; index-- {
		selected := apps[index]
		callback := fmt.Sprintf("https://%s/api/auth/callback/provider?code=opaque&state=%s-state", oauthHost, selected.name)
		redirect := visit(callback)
		if redirect.StatusCode != http.StatusSeeOther || redirect.Header.Get("Location") != "https://"+selected.hostname+"/api/auth/callback/provider?code=opaque&state="+selected.name+"-state" {
			t.Fatalf("%s routed to %d %q", selected.name, redirect.StatusCode, redirect.Header.Get("Location"))
		}
		if response := visit(redirect.Header.Get("Location")); response.StatusCode != http.StatusNoContent {
			t.Fatalf("%s callback returned %d", selected.name, response.StatusCode)
		}
		select {
		case got := <-selected.callbacks:
			if got != "code=opaque&state="+selected.name+"-state session="+selected.name {
				t.Fatalf("%s callback received %q", selected.name, got)
			}
		default:
			t.Fatalf("%s never received its callback", selected.name)
		}
		if response := visit(callback); response.StatusCode != http.StatusGone {
			t.Fatalf("%s state replay returned %d", selected.name, response.StatusCode)
		}
	}
	for _, app := range apps {
		if len(app.callbacks) != 0 {
			t.Fatalf("%s received another service's callback", app.name)
		}
	}
}
