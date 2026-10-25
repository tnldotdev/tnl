package daemon

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
)

// this local proxy models Fly's service-check decision without terminating
// visitor TLS. deployed qualification separately exercises the actual Fly edge.
func TestIntegrationSplitIngressProxyFailover(t *testing.T) {
	transport := &http.Transport{DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	health := &http.Client{Transport: transport, Timeout: time.Second}
	var mu sync.RWMutex
	var second string
	var selected [2]atomic.Int32
	sockets := runtimeListeners{ingress: serviceRuntimeListener(t), metrics: serviceRuntimeListener(t)}
	fixture := newSplitPublishFixtureWithOptions(t, "ingress-failover", splitPublishOptions{
		proxyIngress: true,
		configureProcess: func(config *daemonconfig.Config) {
			if config.Role == daemonconfig.RoleRelay {
				config.Region = "sjc"
			}
			if config.Role == daemonconfig.RoleIngress {
				config.Region = "sjc"
				config.RequireProxyHeader, config.IngressTrustedProxies = true, []string{"127.0.0.1/32"}
				config.IngressConnectorPort = 4443
			}
		},
		selectIngress: func(first string) string {
			mu.RLock()
			addresses := []string{first, second}
			mu.RUnlock()
			for index, address := range addresses {
				if address == "" {
					continue
				}
				response, err := health.Get("http://" + address + "/ready")
				if err != nil {
					continue
				}
				_ = response.Body.Close()
				if response.StatusCode == http.StatusNoContent {
					selected[index].Add(1)
					return address
				}
			}
			return ""
		},
	})
	config := fixture.ingressConfig
	config.IngressID, config.IngressConnectorPort = "ingress-split-b", 4444
	config.Region = "ord"
	config.IngressListen, config.MetricsListen = sockets.ingress.Addr().String(), sockets.metrics.Addr().String()
	config.IngressUDPListen = ""
	process := startIntegrationProcessWithOptions(t, config, integrationProcessOptions{
		acmeHTTPClient: fixture.pebble.httpClient, serviceHTTPClient: fixture.serviceHTTP,
		relayClientTLS: fixture.roots, owner: fixture.owner, listeners: sockets,
	})
	waitForProcessReady(t, process)
	mu.Lock()
	second = config.IngressListen
	mu.Unlock()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "same public url") }))
	cleanupIntegrationHTTPServer(t, target, fixture.owner)
	quic, tcp := fixture.connectors()
	ready := waitForPublisherReady(t, fixture.startPublisher(t, target.URL, quic, tcp))
	waitForReadyPublisherConnections(t, fixture.inspect, ready.PublicURLID, ready.PublishRunNumber, 2)
	waitForIngressRoutingCurrent(t, fixture.inspect, 2)
	waitForPreparedPublicVisitor(t, fixture.visitor, ready.PublicURL)
	assertRequest := func() {
		t.Helper()
		response, body, err := fixture.visitor.requestURL(http.MethodGet, ready.PublicURL+"/same", nil)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK || string(body) != "same public url" {
			t.Fatalf("public request: status=%d body=%q", response.StatusCode, body)
		}
	}
	assertRequest()
	t.Log("shared public url: first ingress returned HTTP 200")
	if selected[0].Load() == 0 {
		t.Fatal("initial request did not reach the first ingress")
	}
	stopIntegrationProcess(t, fixture.ingress)
	waitForPreparedPublicVisitor(t, fixture.visitor, ready.PublicURL)
	for range 5 {
		assertRequest()
	}
	if selected[1].Load() < 5 {
		t.Fatal("fresh requests did not reach the surviving ingress")
	}
	byDirection := make(map[string]float64)
	for _, relay := range []*integrationProcess{fixture.relayA.process, fixture.relayB.process} {
		response, err := health.Get("http://" + relay.metricsAddress + "/metrics")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatal("read regional relay transfer metrics", err)
		}
		for _, line := range strings.Split(string(body), "\n") {
			if !strings.HasPrefix(line, "tnl_relay_ingress_transfer_bytes_total{") ||
				!strings.Contains(line, `tnl_ingress_region="ord"`) || !strings.Contains(line, `tnl_relay_region="sjc"`) {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) != 2 {
				t.Fatal("invalid regional relay transfer metric", line)
			}
			bytes, err := strconv.ParseFloat(fields[1], 64)
			if err != nil {
				t.Fatal(err)
			}
			for _, direction := range []string{"visitor_to_publisher", "publisher_to_visitor"} {
				if strings.Contains(line, `tnl_direction="`+direction+`"`) {
					byDirection[direction] += bytes
				}
			}
		}
	}
	if byDirection["visitor_to_publisher"] == 0 || byDirection["publisher_to_visitor"] == 0 {
		t.Fatal("cross-region traffic lost directional byte accounting", byDirection)
	}
	t.Log("shared public url: first ingress stopped; surviving ingress returned HTTP 200 for five fresh requests")
}
