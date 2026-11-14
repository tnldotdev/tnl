package daemon

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	projectconfig "github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
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
	var authority atomic.Value
	authority.Store("")
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil || string(data) != body || r.Header.Get("Stripe-Signature") != "signed-body" || r.Host != authority.Load().(string) || r.Header.Get("X-Forwarded-For") != "127.0.0.1" {
			t.Errorf("webhook forwarding changed its inputs: %q %q %q %v", data, r.Host, r.Header, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		observed <- r.URL.RequestURI()
		w.WriteHeader(http.StatusNoContent)
	}))
	cleanupIntegrationHTTPServer(t, target, fixture.owner)
	tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: server, Project: t.TempDir(), Service: "api", Target: target.URL, IntegrationScope: group})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tunnel.Finish(context.Background(), nil) })
	id, err := opaqueid.New(opaqueid.PublicURLPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetPublicURL(t.Context(), id, "https://app.example"); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetProvisioning(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetReady(t.Context(), "https://app.example", 1); err != nil {
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
	quic, tcp := fixture.connectors()
	var previous publisher.Event
	for range 2 {
		handler, prefixes, err := integrations.NewWebhooks(t.Context(), state, server, group, hostname, map[string]projectconfig.Webhook{"stripe": definition}, nil)
		if err != nil {
			t.Fatal(err)
		}
		config := fixture.identity.publisherConfig("", quic, tcp)
		config.Purpose, config.Handler, config.AllowedIPPrefixes = controlv1.Webhooks, handler, prefixes
		handle := startOwnedIntegrationPublisher(t, fixture.owner, config, fixture.diagnostics)
		ready := fixture.waitReady(t, handle)
		authority.Store(strings.TrimPrefix(ready.PublicURL, "https://"))
		if previous.PublicURLID != "" && (ready.PublicURLID != previous.PublicURLID || ready.PublicURL != previous.PublicURL || ready.PublishRunNumber <= previous.PublishRunNumber) {
			t.Fatalf("webhook restart replaced its saved URL or reused run: %+v -> %+v", previous, ready)
		}
		saved, err := fixture.identity.routes.GetPublicURLByHostname(t.Context(), fixture.identity.teamID, hostname)
		if err != nil || saved.Target != "" || saved.Ephemeral || saved.Purpose != controlv1.Webhooks {
			t.Fatalf("webhook reload = %+v, %v", saved, err)
		}
		request, err := http.NewRequest(http.MethodPost, ready.PublicURL+"/hooks/stripe?event=one", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
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
