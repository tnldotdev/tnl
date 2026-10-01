package tnldruntime

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/proxyproto"
)

func TestControlProxyListenerUsesVisitorAddressWithoutBlockingOtherConnections(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = io.WriteString(response, request.RemoteAddr)
	}))
	server.Listener = controlProxyListener{Listener: server.Listener}
	server.StartTLS()
	t.Cleanup(server.Close)

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	clientTLS := &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12}
	connect := func() net.Conn {
		t.Helper()
		conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}

	// a connection that never sends its PROXY header must not stall Accept.
	_ = connect()
	if err := tls.Client(connect(), clientTLS).Handshake(); err == nil {
		t.Fatal("public control accepted TLS without the required PROXY v2 header")
	}
	for _, source := range []string{"203.0.113.10:12345", "203.0.113.11:12346"} {
		conn := connect()
		header, err := proxyproto.Encode(proxyproto.Header{
			Source: netip.MustParseAddrPort(source), Destination: netip.MustParseAddrPort("198.51.100.10:443"),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(header); err != nil {
			t.Fatal(err)
		}
		secure := tls.Client(conn, clientTLS)
		if err := secure.Handshake(); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(secure, "GET /v1/client-ip HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(secure), nil)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK || string(body) != source {
			t.Fatalf("address = %q, response status = %d, error = %v; want %q", body, response.StatusCode, err, source)
		}
	}
}
