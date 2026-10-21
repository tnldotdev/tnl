package clientruntime

import (
	"io"
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

func TestPingAddressRequiresPublicHTTPAndNoCredentials(t *testing.T) {
	for _, address := range []string{"db.example:5432", "postgres://db.example:5432", "https://user:pass@site.example", "https://site.example/#token"} {
		if _, _, err := PingAddress(address, ""); err == nil {
			t.Fatalf("accepted %q", address)
		}
	}
	if address, protocol, err := PingAddress("https://site.example/health", "http"); err != nil || address != "https://site.example/health" || protocol != "https" {
		t.Fatalf("address=%s protocol=%s err=%v", address, protocol, err)
	}
}

func TestPingRequiresVerifiedPublicTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	if result := Ping(t.Context(), server.URL, "https"); result.State != "unavailable" || result.Note != "connection or TLS verification failed" {
		t.Fatalf("untrusted public certificate accepted: %+v", result)
	}
	for _, protocol := range []string{"postgres", "mysql", "redis", "ssh", "tcp"} {
		if _, _, err := PingAddress("db.example:5432", protocol); err == nil {
			t.Fatalf("accepted retired public protocol %s", protocol)
		}
		if result := Ping(t.Context(), "127.0.0.1:1", protocol); result.State != "invalid protocol" {
			t.Fatalf("retired protocol %s: %+v", protocol, result)
		}
	}
}
