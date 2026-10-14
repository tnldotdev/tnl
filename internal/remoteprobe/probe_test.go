package remoteprobe

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPProbeUsesVisitorTLSAndDoesNotFollowRedirects(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("remote probe sent an application credential")
		}
		switch r.URL.Path {
		case "/login":
			w.WriteHeader(http.StatusUnauthorized)
		case "/denied":
			w.Header().Set("Tnl-Error-Code", "TNL_IP_POLICY_DENIED")
			w.WriteHeader(http.StatusForbidden)
		case "/redirect":
			http.Redirect(w, r, "https://unrelated.example/", http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()
	for _, test := range []struct {
		path      string
		reachable bool
		status    int
		reason    string
	}{
		{"/", true, 200, ""},
		{"/login", true, 401, ""},
		{"/denied", false, 403, "remote.denied"},
		{"/redirect", true, 302, ""},
	} {
		result, err := Probe(t.Context(), Selection{Address: server.URL, Path: test.path, HTTPTransport: server.Client().Transport})
		if err != nil || result.Reachable != test.reachable || result.HTTPStatus != test.status || result.Reason != test.reason {
			t.Fatalf("probe %s = %+v, %v", test.path, result, err)
		}
	}
	result, err := Probe(t.Context(), Selection{Address: server.URL})
	if err != nil || result.Reachable || result.Reason != "remote.tls_failed" {
		t.Fatalf("untrusted visitor TLS was accepted: %+v, %v", result, err)
	}
}

func TestSSHProbeWaitsForTargetBanner(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = io.WriteString(connection, "SSH-2.0-test-server\r\n")
	}()
	selected := Selection{Address: listener.Addr().String(), Protocol: "ssh"}
	result, err := Probe(t.Context(), selected)
	if err != nil || !result.Reachable || result.Protocol != "ssh" {
		t.Fatalf("SSH visitor banner = %+v, %v", result, err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	result, err = Probe(context.Background(), selected)
	if err != nil || result.Reachable || result.Reason != "remote.no_response" {
		t.Fatalf("closed SSH target = %+v, %v", result, err)
	}
}
