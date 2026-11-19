package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/testutil"
)

// use the real Vite host filter and native app preparation, not a replacement
// HTTP handler. the connector changes only socket addressing, never HTTP Host.
func TestIntegrationConnectorOnlyViteCanonicalHost(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	f := newServiceRuntimeFixture(t, false, nil)
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "index.html"), []byte("<h1>connector Vite fixture</h1>"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.inspect.ExecContext(t.Context(), `DELETE FROM control.ingress_service_port_ranges`); err != nil {
		t.Fatal(err)
	}
	controlTransport := f.publicHTTP.Transport.(*http.Transport).Clone()
	controlTransport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		hostname, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		if hostname == "control.private.integration.test" {
			address = f.publicControlAddress
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	t.Cleanup(controlTransport.CloseIdleConnections)
	quic, tcp := f.connectors()
	native := startFrameworkNativeOwner(t, directory, config.Services{"web": {Public: new(false)}, "unrelated": {}},
		frameworkNativeSetup{controlURL: "https://control.private.integration.test", state: f.identity.state,
			controlHTTP: &http.Client{Transport: controlTransport}, relayTLS: f.roots, quic: quic, tcp: tcp})
	defer native.stop()
	command := exec.Command("node", filepath.Join(integrationRepositoryRoot(t), "packages/ts/test/fixtures/connector-vite.ts"))
	command.Dir = directory
	command.Env = append(os.Environ(), "TNL_APP_ENDPOINT="+native.endpoint, "TNL_NO_TELEMETRY=1", "TNL_PREVIEW=required")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr synchronizedBuffer
	command.Stderr = &stderr
	process, err := startOwnedCommand(command, nil)
	if err != nil {
		t.Fatal(err)
	}
	scanned, line := make(chan struct{}), make(chan string, 1)
	go func() {
		defer close(scanned)
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			line <- scanner.Text()
		} else {
			line <- ""
		}
	}()
	defer func() {
		if err := process.shutdown(10*time.Second, 3*time.Second); err != nil {
			t.Error("Vite cleanup", err)
		}
		if err := waitForDoneWithin(scanned, time.Second); err != nil {
			t.Error("Vite output reader did not join", err)
		}
		if err := process.result(); err != nil {
			t.Error("Vite process", err, stderr.String())
		}
	}()
	var ready struct {
		Port int `json:"port"`
	}
	select {
	case value := <-line:
		if err := json.Unmarshal([]byte(value), &ready); err != nil || ready.Port <= 0 {
			t.Fatal("real Vite did not bind", err, stderr.String())
		}
	case <-time.After(45 * time.Second):
		t.Fatal("real Vite did not start", stderr.String())
	}
	var serviceID string
	select {
	case serviceID = <-native.routable:
	case <-time.After(35 * time.Second):
		t.Fatal("connector-only Vite publication did not become routable", stderr.String())
	}
	service, err := f.identity.routes.GetService(t.Context(), serviceID)
	if err != nil || service.Endpoint == nil || service.Endpoint.Public || service.Endpoint.Port != 443 {
		t.Fatal("Vite lost its connector-only HTTP identity", err)
	}
	person, err := f.identity.authority.IdentityContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	control, err := connectorstream.NewControl(f.identity.routes, f.identity.state, person.Identity.Id)
	if err != nil {
		t.Fatal(err)
	}
	listener, stopConnector := startRuntimeConnector(t, f, service, connectorstream.Config{
		Control: control, IdentityID: person.Identity.Id, RelayQUIC: quic, RelayWebSocket: tcp})
	defer stopConnector()
	transport := &http.Transport{Proxy: nil, TLSClientConfig: f.visitorRoots.Clone(),
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	response, err := client.Get("https://" + service.Endpoint.Hostname + "/")
	if err != nil {
		t.Fatal("connector request with canonical Host failed", err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || !strings.Contains(string(body), "connector Vite fixture") {
		t.Fatalf("real Vite rejected the connector's canonical Host: status=%d body=%q: %v", response.StatusCode, body, err)
	}
	unrelated, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+service.Endpoint.Hostname+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	unrelated.Host = "unrelated.example"
	rejected, err := client.Do(unrelated)
	if err != nil {
		t.Fatal("connector Host rejection failed", err)
	}
	rejectedBody, readErr := io.ReadAll(rejected.Body)
	_ = rejected.Body.Close()
	if readErr != nil || rejected.StatusCode != http.StatusForbidden || !strings.Contains(string(rejectedBody), "Blocked request") {
		t.Fatalf("real Vite did not reject the connector's unrelated Host: status=%d body=%q: %v", rejected.StatusCode, rejectedBody, readErr)
	}
	// admitted connector HTTP preserves Host rather than imposing public endpoint
	// authority. also verify the same Vite host filter through its local listener.
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(ready.Port))+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "unrelated.example"
	localTransport := &http.Transport{Proxy: nil}
	defer localTransport.CloseIdleConnections()
	blocked, err := (&http.Client{Transport: localTransport, Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(blocked.Body)
	_ = blocked.Body.Close()
	if err != nil || blocked.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "Blocked request") {
		t.Fatalf("real Vite allowed an unrelated Host: status=%d body=%q: %v", blocked.StatusCode, body, err)
	}
	var services, endpoints, claims, ingress int
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT (SELECT count(*) FROM control.services),
		(SELECT count(*) FROM control.service_endpoints WHERE public),
		(SELECT count(*) FROM control.service_port_claims), (SELECT count(*) FROM control.ingress_leases)`).
		Scan(&services, &endpoints, &claims, &ingress); err != nil || services != 1 || endpoints != 0 || claims != 0 || ingress != 0 {
		t.Fatalf("connector-only Vite realized unrelated services or ingress: services=%d public=%d claims=%d ingress=%d: %v", services, endpoints, claims, ingress, err)
	}
}
