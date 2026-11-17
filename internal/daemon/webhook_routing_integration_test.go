package daemon

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	projectconfig "github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/publisher/integrations"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationWebhookHandlerReloadsTargetlessPublicURL(t *testing.T) {
	fixture := newStandalonePublishFixture(t, "webhook-reload")
	state, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(fixture.owner.directory, "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	server, hostname := fixture.identity.controlOrigin, fixture.identity.hostname
	group := clientstate.IntegrationScope{PrimaryProjectRoot: t.TempDir(), Namespace: "member.example"}
	const body = "{\"event\":\"paid\"}\n"
	observed := make(chan string, 2)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil || string(data) != body || r.Header.Get("Stripe-Signature") != "signed-body" || r.Host != hostname || r.Header.Get("X-Forwarded-For") != "127.0.0.1" {
			t.Errorf("webhook forwarding changed its inputs: %q %q %q %v", data, r.Host, r.Header, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		observed <- r.URL.RequestURI()
		w.WriteHeader(http.StatusNoContent)
	}))
	cleanupIntegrationHTTPServer(t, target, fixture.owner)
	quic, tcp := fixture.connectors()
	appHostname := "api." + strings.TrimPrefix(hostname, "webhook-reload.")
	appService, appConfig := fixture.identity.prepareService(t, target.URL, quic, tcp, controlv1.ProjectServiceConfiguration{Hostname: &appHostname})
	appPublisher := startOwnedIntegrationPublisher(t, fixture.owner, appConfig, fixture.diagnostics)
	appRun := waitForPublisherReady(t, appPublisher)
	waitForReadyPublisherConnections(t, fixture.inspect, appRun.ServiceId, appRun.RunNumber, 2)
	tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: server, Project: t.TempDir(), Service: "api", ServiceID: appService.Id, ServiceProtocol: "http", Target: target.URL, IntegrationScope: group})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tunnel.Finish(context.Background(), nil) })
	if err := tunnel.SetProvisioning(t.Context(), uint64(appRun.RunNumber)); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetReady(t.Context(), serviceHTTPAddress(appRun), uint64(appRun.RunNumber)); err != nil {
		t.Fatal(err)
	}
	definition := projectconfig.Webhook{Service: "api", Path: "/hooks/stripe", Provider: "stripe", SourceIPs: []string{"127.0.0.1/32"}}
	encoded, _, err := integrations.DefinitionBytes(definition)
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnel.RegisterWebhookEndpoint(t.Context(), "stripe", encoded); err != nil {
		t.Fatal(err)
	}
	var previous controlv1.ServiceRunPreparation
	for range 2 {
		handler, prefixes, err := integrations.NewWebhooks(t.Context(), state, server, group, hostname, map[string]projectconfig.Webhook{"stripe": definition}, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, config := fixture.identity.prepareService(t, "", quic, tcp, controlv1.ProjectServiceConfiguration{
			Http: &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectHTTPAccess{Ip: &prefixes}},
		})
		config.Handler = handler
		handle := startOwnedIntegrationPublisher(t, fixture.owner, config, fixture.diagnostics)
		ready := fixture.waitReady(t, handle)
		if previous.ServiceId != "" && (ready.ServiceId != previous.ServiceId || ready.ServiceRunId == previous.ServiceRunId || ready.RunNumber <= previous.RunNumber) {
			t.Fatalf("webhook restart replaced its saved URL or reused run: %+v -> %+v", previous, ready)
		}
		saved, err := fixture.identity.routes.GetService(t.Context(), ready.ServiceId)
		declaration, _, declarationErr := fixture.identity.routes.GetServiceConfiguration(t.Context(), ready.ServiceId)
		if err != nil || declarationErr != nil || declaration == nil || declaration.Target != "app" || saved.Ephemeral || saved.Endpoint == nil || saved.Endpoint.Hostname != hostname {
			t.Fatalf("webhook reload = %+v, %v", saved, err)
		}
		request, err := http.NewRequest(http.MethodPost, serviceHTTPAddress(ready)+"/hooks/stripe?event=one", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Stripe-Signature", "signed-body")
		response, _, err := fixture.visitor.request(request)
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("webhook visitor response = %v, %v", response, err)
		}
		select {
		case path := <-observed:
			if path != "/hooks/stripe?event=one" {
				t.Fatalf("webhook path = %q", path)
			}
		default:
			t.Fatal("webhook did not reach registered receiver")
		}
		fixture.visitor.transport.CloseIdleConnections()
		stopIntegrationPublisher(t, handle)
		previous = ready
	}
}
