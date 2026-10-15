package clientruntime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPingHTTPVisitorBoundary(t *testing.T) {
	for _, test := range []struct {
		status      int
		code, state string
	}{
		{200, "", "responding"}, {403, "TNL_IP_POLICY_DENIED", "tnl denied"},
		{503, "", "app responded"}, {302, "", "redirected (not followed)"},
	} {
		calls := 0
		result := pingWithTransport(t.Context(), "https://app.example/health", "https", roundTrip(func(request *http.Request) (*http.Response, error) {
			calls++
			if request.Method != "GET" || request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" || request.URL.Path != "/health" {
				t.Fatalf("unexpected visitor request: %#v", request)
			}
			if deadline, ok := request.Context().Deadline(); !ok || time.Until(deadline) > 5*time.Second {
				t.Fatal("missing bounded deadline")
			}
			return &http.Response{StatusCode: test.status, Header: http.Header{DiagnosticHeader: []string{test.code}, "Location": []string{"https://elsewhere.example"}}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
		}))
		if calls != 1 || result.State != test.state || result.Status != test.status || result.Code != test.code {
			t.Fatalf("result=%+v calls=%d", result, calls)
		}
	}
}

func TestPingAddressRequiresExplicitTCPProtocolAndNoCredentials(t *testing.T) {
	for _, address := range []string{"db.example:5432", "https://user:pass@site.example", "https://site.example/#token"} {
		if _, _, err := PingAddress(address, ""); err == nil {
			t.Fatalf("accepted %q", address)
		}
	}
	if address, protocol, err := PingAddress("db.example:5432", "postgres"); err != nil || address != "db.example:5432" || protocol != "postgres" {
		t.Fatalf("address=%s protocol=%s err=%v", address, protocol, err)
	}
}

func TestRedisPingStopsAtVerifiedTLSWithoutSendingCommands(t *testing.T) {
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := fixture.TLS.Certificates[0]
	pool := x509.NewCertPool()
	pool.AddCert(fixture.Certificate())
	fixture.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer connection.Close()
		secure := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		if err := secure.Handshake(); err != nil {
			done <- err
			return
		}
		_ = secure.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		var byteRead [1]byte
		count, _ := secure.Read(byteRead[:])
		if count != 0 {
			done <- io.ErrUnexpectedEOF
			return
		}
		done <- nil
	}()
	result := pingTCP(context.Background(), PingResult{Address: listener.Addr().String(), Protocol: "redis", State: "unavailable"}, &tls.Config{RootCAs: pool})
	if result.State != "tls verified" {
		t.Fatalf("ping = %+v", result)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
