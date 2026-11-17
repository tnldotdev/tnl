package daemon

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/serverhttp"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

func TestIntegrationExpiredIngressRestartsAndRecoversVisitors(t *testing.T) {
	fixture := newSplitPublishFixture(t, "ingress-restart")
	var requests atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, "ingress recovered")
	}))
	cleanupIntegrationHTTPServer(t, target, fixture.owner)
	quic, tcp := fixture.connectors()
	publisher := fixture.startPublisher(t, target.URL, quic, tcp)
	ready := fixture.waitReady(t, publisher)
	before := readSplitIngressLease(t, fixture.inspect, fixture.ingressConfig.IngressID)
	response, body, err := fixture.visitor.requestURL(http.MethodGet, serviceHTTPAddress(ready), nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "ingress recovered" || requests.Load() != 1 {
		t.Fatalf("initial visitor = %s, %q, target requests = %d", response.Status, body, requests.Load())
	}
	assertIntegrationPublicURLCertificate(t, response, ready.Hostname)
	// availability expiry alone permits the same run to renew while serving
	// authority remains current. expire both for this exact run so the next
	// real control operation rejects it and a replacement can register.
	// the process must propagate that terminal error through ordinary shutdown.
	result, err := fixture.inspect.ExecContext(integrationOperationContext(t), `
		UPDATE control.ingress_leases
		SET lease_expires_at = renewed_at + interval '1 microsecond',
			serving_until = renewed_at + interval '1 microsecond'
		WHERE ingress_id = $1 AND ingress_run_id = $2 AND ingress_lease_revision = $3
	`, fixture.ingressConfig.IngressID, before.runID, before.revision)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		t.Fatalf("expired ingress lease rows = %d, error = %v", count, err)
	}
	retired := fixture.ingress
	if err := retired.wait(); !expiredIngressExit(err) {
		t.Fatalf("expired ingress exit = %v", err)
	}
	// acknowledge the expected exit so topology cleanup still checks every run.
	retired.mu.Lock()
	retired.err = nil
	retired.mu.Unlock()
	if _, _, err := fixture.visitor.requestURL(http.MethodGet, serviceHTTPAddress(ready), nil); err == nil {
		t.Fatal("stopped ingress still served visitors")
	}
	fixture.ingress = startIntegrationProcessWithOptions(t, fixture.ingressConfig, integrationProcessOptions{acmeHTTPClient: fixture.pebble.httpClient, serviceHTTPClient: fixture.serviceHTTP, relayClientTLS: fixture.roots, owner: fixture.owner})
	waitForProcessReady(t, fixture.ingress)
	waitForIngressRoutingCurrent(t, fixture.inspect, 1)
	after := readSplitIngressLease(t, fixture.inspect, fixture.ingressConfig.IngressID)
	if after.runID == before.runID || after.revision != before.revision+1 {
		t.Fatalf("restart lease: before=%+v after=%+v", before, after)
	}
	response, body, err = fixture.visitor.requestURL(http.MethodGet, serviceHTTPAddress(ready), nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "ingress recovered" {
		t.Fatalf("recovered visitor = %s, %q", response.Status, body)
	}
	assertIntegrationPublicURLCertificate(t, response, ready.Hostname)
	if requests.Load() != 2 {
		t.Fatalf("target requests = %d, want 2 without replay or stopped-ingress traffic", requests.Load())
	}
	assertServiceRunNumber(t, fixture.inspect, ready.ServiceId, ready.RunNumber)
}

// the routing refresh may join its stale-lease response with the terminal
// sentinel. no independent operation or cleanup error may be acknowledged.
func expiredIngressExit(err error) bool {
	if !errors.Is(err, ingress.ErrIngressLeaseLost) {
		return false
	}
	var expected func(error) bool
	expected = func(err error) bool {
		if err == ingress.ErrIngressLeaseLost {
			return true
		}
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			children := joined.Unwrap()
			if len(children) == 0 {
				return false
			}
			for _, child := range children {
				if !expected(child) {
					return false
				}
			}
			return true
		}
		if cause := errors.Unwrap(err); cause != nil {
			return expected(cause)
		}
		problem, ok := err.(*serverhttp.ProblemError)
		return ok && problem.Status == http.StatusConflict && problem.Code == string(ingressv1.IngressLeaseStale)
	}
	return expected(err)
}
