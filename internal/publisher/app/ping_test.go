package app

import (
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

func TestPingHTTPDoesNotSendCredentialsOrFragments(t *testing.T) {
	for _, address := range []string{"https://user:pass@site.example", "https://site.example/#token"} {
		result := pingWithTransport(t.Context(), address, "https", roundTrip(func(*http.Request) (*http.Response, error) {
			t.Fatalf("attempted HTTP request for %q", address)
			return nil, nil
		}))
		if result.State != "invalid address" {
			t.Fatalf("accepted %q: %+v", address, result)
		}
	}
}

func TestPingRequiresVerifiedPublicTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	if result := Ping(t.Context(), server.URL, "https"); result.State != "unavailable" || result.Note != "connection or TLS verification failed" {
		t.Fatalf("untrusted public certificate accepted: %+v", result)
	}
	for _, protocol := range []string{"postgres", "mysql", "redis", "ssh", "tcp"} {
		if result := Ping(t.Context(), "127.0.0.1:1", protocol); result.State != "invalid protocol" {
			t.Fatalf("retired protocol %s: %+v", protocol, result)
		}
	}
}

func TestPingTCPConnectsWithoutSendingBytes(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	dialAddress := listener.Addr().String()
	address := "postgres://" + dialAddress
	result := PingTCP(t.Context(), address, dialAddress)
	if result.Address != address || result.Protocol != "tcp" || result.State != "tcp connected" || result.Status != 0 || result.Note != "" {
		t.Fatalf("TCP probe: %+v", result)
	}
	deadline := time.Now().Add(time.Second)
	if err := listener.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if n, err := conn.Read(data[:]); n != 0 || err != io.EOF {
		t.Fatalf("TCP probe sent data or did not close: bytes=%d, err=%v", n, err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if result := PingTCP(t.Context(), address, dialAddress); result.State != "unavailable" || result.Note != "TCP connection failed" {
		t.Fatalf("TCP failure: %+v", result)
	}
}
