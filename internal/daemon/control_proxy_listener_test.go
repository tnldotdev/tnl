package daemon

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestControlProxyServesRetainedListener(t *testing.T) {
	owner := newRuntimeTopology(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer backend.Close()
	ca := newTestCertificateAuthority(t)
	const hostname = "control.private.integration.test"
	listener := serviceRuntimeListener(t, owner)
	address := listener.Addr().String()
	serveIntegrationControlProxy(t, owner, listener, strings.TrimPrefix(backend.URL, "http://"), serviceRuntimeTLS(t, ca, hostname))
	if competing, err := net.Listen("tcp", address); err == nil {
		_ = competing.Close()
		t.Fatal("proxy released its reserved listener before serving")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.roots, ServerName: hostname, MinVersion: tls.VersionTLS13}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get("https://" + address)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal("retained listener did not reach the control backend", response.StatusCode)
	}
}

func TestControlProxyStopAndRecreatePreservesMetadata(t *testing.T) {
	owner := newRuntimeTopology(t)
	backend := func(name string) *httptest.Server {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"backend": name, "host": r.Host,
				"source": r.Header.Get("X-Forwarded-For"), "scheme": r.Header.Get("X-Forwarded-Proto"),
			})
		}))
		owner.cleanupResource(t, server.Close)
		return server
	}
	controlA, controlB := backend("control-a"), backend("control-b")
	ca := newTestCertificateAuthority(t)
	const hostname = "control.private.integration.test"
	secure := serviceRuntimeTLS(t, ca, hostname)
	listenerA, listenerB := serviceRuntimeListener(t, owner), serviceRuntimeListener(t, owner)
	addressA, addressB := listenerA.Addr().String(), listenerB.Addr().String()
	stopA := serveIntegrationControlProxy(t, owner, listenerA, strings.TrimPrefix(controlA.URL, "http://"), secure)
	serveIntegrationControlProxy(t, owner, listenerB, strings.TrimPrefix(controlB.URL, "http://"), secure)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.roots, ServerName: hostname, MinVersion: tls.VersionTLS13}}
	owner.cleanupResource(t, transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	check := func(address, wantBackend string) {
		t.Helper()
		request, err := http.NewRequestWithContext(integrationOperationContext(t), http.MethodGet, "https://"+address+"/identity", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = hostname
		request.Header.Set("X-Forwarded-For", "203.0.113.99")
		request.Header.Set("X-Forwarded-Proto", "http")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var got map[string]string
		if err := json.NewDecoder(response.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"backend": wantBackend, "host": hostname, "source": "127.0.0.1", "scheme": "https"}
		if response.StatusCode != http.StatusOK || !reflect.DeepEqual(got, want) {
			t.Fatalf("control proxy status=%d metadata=%v, want %v", response.StatusCode, got, want)
		}
	}
	check(addressA, "control-a")
	check(addressB, "control-b")
	stopA()
	controlA.Close()
	if connection, err := new(net.Dialer).DialContext(integrationOperationContext(t), "tcp", addressA); err == nil {
		_ = connection.Close()
		t.Fatal("stopped control left its public front door accepting connections")
	}
	check(addressB, "control-b")
	replacement := backend("replacement")
	listener, err := net.Listen("tcp", addressA)
	if err != nil {
		t.Fatal(err)
	}
	stopReplacement := serveIntegrationControlProxy(t, owner, listener, strings.TrimPrefix(replacement.URL, "http://"), secure)
	// a retained cleanup must stop its own incarnation, not the replacement.
	stopA()
	check(addressA, "replacement")
	check(addressB, "control-b")
	stopReplacement()
	stopReplacement()
	check(addressB, "control-b")
}
