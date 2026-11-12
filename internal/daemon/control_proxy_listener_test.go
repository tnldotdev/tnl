package daemon

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
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
