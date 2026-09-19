package tnldruntime

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tnldotdev/tnl/internal/ingress"
)

func TestIntegrationExpiredIngressRestartsAndRecoversVisitors(t *testing.T) {
	fixture := newSplitPublishFixture(t, "ingress-restart")
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ingress recovered") }))
	cleanupIntegrationHTTPServer(t, target, fixture.owner)
	quic, tcp := fixture.connectors()
	publisher := fixture.startPublisher(t, target.URL, quic, tcp)
	ready := fixture.waitReady(t, publisher)
	before := readSplitIngressLease(t, fixture.inspect, fixture.ingressConfig.IngressID)
	if _, _, err := fixture.visitor.requestURL(http.MethodGet, ready.PublicURL, nil); err != nil {
		t.Fatal(err)
	}
	// Make the next real control operation reject the exact run. The process
	// must propagate that terminal error through its ordinary shutdown path.
	if _, err := fixture.inspect.ExecContext(integrationOperationContext(t), `UPDATE control.ingress_leases SET lease_expires_at = renewed_at + interval '1 microsecond' WHERE ingress_id = $1`, fixture.ingressConfig.IngressID); err != nil {
		t.Fatal(err)
	}
	retired := fixture.ingress
	if err := retired.wait(); !errors.Is(err, ingress.ErrIngressLeaseLost) {
		t.Fatalf("expired ingress exit = %v", err)
	}
	// Acknowledge the expected exit so topology cleanup still checks every run.
	retired.mu.Lock()
	retired.err = nil
	retired.mu.Unlock()
	if _, _, err := fixture.visitor.requestURL(http.MethodGet, ready.PublicURL, nil); err == nil {
		t.Fatal("stopped ingress still served visitors")
	}
	fixture.ingress = startIntegrationProcessWithOptions(t, fixture.ingressConfig, integrationProcessOptions{acmeHTTPClient: fixture.pebble.httpClient, serviceHTTPClient: fixture.serviceHTTP, relayClientTLS: fixture.roots, owner: fixture.owner})
	waitForProcessReady(t, fixture.ingress)
	waitForIngressRoutingCurrent(t, fixture.inspect, 1)
	after := readSplitIngressLease(t, fixture.inspect, fixture.ingressConfig.IngressID)
	if after.runID == before.runID || after.revision != before.revision+1 {
		t.Fatalf("restart lease: before=%+v after=%+v", before, after)
	}
	response, body, err := fixture.visitor.requestURL(http.MethodGet, ready.PublicURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "ingress recovered" {
		t.Fatalf("recovered visitor = %s, %q", response.Status, body)
	}
	assertRouteVersion(t, fixture.inspect, ready.RouteID, ready.RouteVersion)
}
