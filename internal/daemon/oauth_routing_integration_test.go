package daemon

import (
	"context"
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
		config         publisherservice.RunConfig
		publisher      *integrationPublisher
		run            controlv1.ServiceRunPreparation
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
				value := request.URL.Query().Get("state")
				if value == "" {
					value = name + "-state"
				}
				query.Set("state", value)
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
		config.HTTPAdmitRequest = integrations.OAuthAdmission(state, server)
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
		apps = append(apps, app{name: name, hostname: hostname, callbacks: observed, tunnel: tunnel, config: config, publisher: handle, run: ready})
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
		query := "code=a%2fb%2Bc+z&state=" + selected.name + "-state&scope=a%20b&scope="
		callback := "https://" + oauthHost + "/api/auth/callback/provider?" + query
		redirect := visit(callback)
		if redirect.StatusCode != http.StatusSeeOther || redirect.Header.Get("Location") != "https://"+selected.hostname+"/api/auth/callback/provider?"+query {
			t.Fatalf("%s routed to %d %q", selected.name, redirect.StatusCode, redirect.Header.Get("Location"))
		}
		if response := visit(redirect.Header.Get("Location")); response.StatusCode != http.StatusNoContent {
			t.Fatalf("%s callback returned %d", selected.name, response.StatusCode)
		}
		select {
		case got := <-selected.callbacks:
			if got != query+" session="+selected.name {
				t.Fatalf("%s callback received %q", selected.name, got)
			}
		default:
			t.Fatalf("%s never received its callback", selected.name)
		}
		if response := visit(redirect.Header.Get("Location")); response.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("%s final-hop replay returned %d", selected.name, response.StatusCode)
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
	selected := apps[0]
	if response := visit("https://" + selected.hostname + "/login?state=between-hops"); response.StatusCode != http.StatusFound {
		t.Fatal("login before replacement failed")
	}
	const providerQuery = "code=a%2fb%2Bc+z&state=between-hops&provider=&provider=x%2Fy"
	redirect := visit("https://" + oauthHost + "/api/auth/callback/provider?" + providerQuery)
	if redirect.StatusCode != http.StatusSeeOther || redirect.Header.Get("Location") != "https://"+selected.hostname+"/api/auth/callback/provider?"+providerQuery {
		t.Fatal("callback before replacement changed provider query bytes", redirect.StatusCode, redirect.Header.Get("Location"))
	}
	// hold the final browser request until the same service has a replacement
	// run. ingress must reach that run, whose admission must reject the code.
	stopIntegrationPublisher(t, selected.publisher)
	selected.publisher = startOwnedIntegrationPublisher(t, fixture.owner, selected.config, fixture.diagnostics)
	replacement := waitForPublisherReady(t, selected.publisher)
	if replacement.ServiceId != selected.run.ServiceId || replacement.ServiceRunId == selected.run.ServiceRunId || replacement.RunNumber <= selected.run.RunNumber {
		t.Fatal("app replacement did not use a new run of the same service", selected.run, replacement)
	}
	waitForReadyPublisherConnections(t, fixture.inspect, replacement.ServiceId, replacement.RunNumber, 2)
	waitForAppliedServiceRouting(t, fixture.inspect, replacement.ServiceRunId, fixture.process.metricsAddress)
	if response := visit(redirect.Header.Get("Location")); response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("replacement admitted final OAuth hop: %d", response.StatusCode)
	}
	if len(selected.callbacks) != 0 {
		t.Fatal("replacement target received the previous run's OAuth response")
	}
	if response := visit("https://" + selected.hostname + "/api/auth/callback/provider?state=unknown&code=app-owned"); response.StatusCode != http.StatusNoContent {
		t.Fatalf("unknown OAuth state did not remain an ordinary app request: %d", response.StatusCode)
	}
	select {
	case got := <-selected.callbacks:
		if got != "state=unknown&code=app-owned session="+selected.name {
			t.Fatal("unknown-state request lost the app's query or session", got)
		}
	default:
		t.Fatal("unknown-state request never reached the replacement app")
	}
}
