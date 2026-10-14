package remoteprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
		if err != nil || result.Reachable != test.reachable || result.HTTPStatus != test.status || result.Reason != test.reason || !result.TLSVerified {
			t.Fatalf("probe %s = %+v, %v", test.path, result, err)
		}
	}
	result, err := Probe(t.Context(), Selection{Address: server.URL})
	if err != nil || result.Reachable || result.Reason != "remote.tls_failed" || result.TLSVerified {
		t.Fatalf("untrusted visitor TLS was accepted: %+v, %v", result, err)
	}
}

func TestTCPProbeRequiresProtocolAndVerifiedVisitorTLS(t *testing.T) {
	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer certificateServer.Close()
	roots := x509.NewCertPool()
	roots.AddCert(certificateServer.Certificate())
	for _, protocol := range []string{"postgres", "mysql", "redis"} {
		t.Run(protocol, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = listener.Close() })
			completed := make(chan error, 2)
			go func() {
				for range 2 {
					connection, err := listener.Accept()
					if err != nil {
						completed <- err
						return
					}
					func() {
						defer connection.Close()
						switch protocol {
						case "postgres":
							var request [8]byte
							if _, err := io.ReadFull(connection, request[:]); err != nil || request != postgresSSLRequest {
								completed <- errors.New("invalid PostgreSQL SSLRequest")
								return
							}
							_, _ = connection.Write([]byte{'S'})
						case "mysql":
							_, _ = connection.Write([]byte{2, 0, 0, 0, 10, 0})
							var request [36]byte
							if _, err := io.ReadFull(connection, request[:]); err != nil || request[3] != 1 || request[5]&(1<<3) == 0 {
								completed <- errors.New("invalid MySQL SSLRequest")
								return
							}
						}
						secure := tls.Server(connection, certificateServer.TLS.Clone())
						completed <- secure.Handshake()
					}()
				}
			}()
			selected := Selection{Address: listener.Addr().String(), Protocol: protocol, TLSRoots: roots}
			result, err := Probe(t.Context(), selected)
			if err != nil || !result.Reachable || !result.TLSVerified {
				t.Fatalf("trusted visitor TLS = %+v, %v", result, err)
			}
			if err := <-completed; err != nil {
				t.Fatal(err)
			}
			selected.TLSRoots = nil
			result, err = Probe(t.Context(), selected)
			if err != nil || result.Reachable || result.Reason != "remote.tls_failed" {
				t.Fatalf("untrusted visitor TLS = %+v, %v", result, err)
			}
			<-completed // the server may see the client close after rejecting its certificate.
		})
	}
}

func TestSSHProbeChecksTargetBanner(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			_, _ = io.WriteString(connection, "SSH-2.0-test-server\r\n")
			_ = connection.Close()
		}
	}()
	selected := Selection{Address: listener.Addr().String(), Protocol: "ssh"}
	result, err := Probe(t.Context(), selected)
	if err != nil || !result.Reachable {
		t.Fatalf("SSH visitor banner = %+v, %v", result, err)
	}
	_ = listener.Close()
	result, err = Probe(context.Background(), selected)
	if err != nil || result.Reachable || result.Reason != "remote.no_response" {
		t.Fatalf("closed SSH visitor path = %+v, %v", result, err)
	}
}

func TestTCPProbeStopsAtCallerDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			defer connection.Close()
			_, _ = io.Copy(io.Discard, connection)
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	result, err := Probe(ctx, Selection{Address: listener.Addr().String(), Protocol: "ssh"})
	if err != nil || result.Reachable || result.Reason != "remote.no_response" {
		t.Fatalf("silent TCP visitor path = %+v, %v", result, err)
	}
}

func TestSelectionRejectsNonVisitorURLs(t *testing.T) {
	for _, selected := range []Selection{
		{Address: "http://example.test"}, {Address: "https://user:secret@example.test"},
		{Address: "https://example.test/path"}, {Address: "https://example.test", Path: "//elsewhere.test"},
		{Address: "example.test:5432", Protocol: "postgres", Path: "/"},
		{Address: "example.test:5432", Protocol: "mongodb"},
	} {
		if err := selected.Validate(); err == nil {
			t.Fatalf("accepted invalid remote selection: %+v", selected)
		}
	}
	if err := (Selection{Address: "https://example.test", Path: "/health?check=1"}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (Selection{Address: "[::1]:5432", Protocol: "postgres"}).Validate(); err != nil {
		t.Fatal(err)
	}
}
