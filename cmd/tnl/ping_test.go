package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPingDoesNotLoadProjectOrSendCredentials(t *testing.T) {
	if _, err := commandForTest(&cli{}, io.Discard)([]string{"ping", "https://example.com", "--protocol", "http"}); err == nil {
		t.Fatal("ping still accepts a redundant protocol override")
	}
	const requestTarget = "/a%2fb/../%7E?q=%2f&z=one+two&z=x"
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(output http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Method != http.MethodGet || request.RequestURI != requestTarget {
			t.Errorf("visitor probe sent %s %q, want GET %q", request.Method, request.RequestURI, requestTarget)
		}
		if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
			t.Error("visitor probe sent credentials")
		}
		output.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	var output, diagnostics bytes.Buffer
	address := server.URL + requestTarget
	stateDir := filepath.Join(t.TempDir(), "must-not-open")
	if err := run(t.Context(), []string{"--config", "missing.yml", "ping", address, "--server", "not a control URL", "--state-dir", stateDir, "--output", "json"}, &output, &diagnostics); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Fatalf("literal ping tried to open client state: %v", err)
	}
	var result publisherapp.PingResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.Address != address || result.Protocol != "http" || result.State != "responding" || result.Status != http.StatusNoContent || requests.Load() != 1 {
		t.Fatalf("ping result=%s, requests=%d, err=%v", output.String(), requests.Load(), err)
	}
}

func TestPingUsesHTTPSForHostnameAndServiceIDWithoutForwardingCredentials(t *testing.T) {
	const (
		hostname  = "example.com"
		serviceID = "svc_0000000000000000000001"
		privateID = "svc_0000000000000000000002"
	)
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	refresh, _, _, err := credentials.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	var visitorCalls, controlCalls atomic.Int32
	visitor := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		visitorCalls.Add(1)
		if r.Host != hostname || r.Method != http.MethodGet || r.RequestURI != "/" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Errorf("unexpected visitor request: %s %s%s", r.Method, r.Host, r.RequestURI)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer visitor.Close()
	control := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		controlCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/v1/discovery" && r.Header.Get("Authorization") != "Bearer "+access.String() {
			t.Error("control did not receive the saved session token")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/discovery":
			_ = json.NewEncoder(w).Encode(controlv1.ControlDiscovery{ManagedDomain: "example.test", ManagedUrlMode: "generated",
				Authentication: controlv1.AuthenticationFacts{Methods: []controlv1.AuthenticationFactsMethods{"oidc"},
					Oidc: &controlv1.OIDCAuthenticationFacts{Issuer: "https://issuer.example.test", LoginFlow: "device_code"}}})
		case "GET /v1/identity":
			_ = json.NewEncoder(w).Encode(authorityv1.IdentityContext{})
		case "GET /v1/visitor/services":
			if query := r.URL.Query(); query.Get("access_path") != "public_endpoint" || query.Has("team_id") {
				t.Errorf("unexpected visitor inventory query: %s", r.URL)
			}
			_ = json.NewEncoder(w).Encode(controlv1.ServicePage{Services: []controlv1.ServiceSummary{
				{Id: privateID, Protocol: controlv1.ServiceProtocolHTTP, Endpoint: &controlv1.ServiceEndpoint{Hostname: hostname, Port: 443}},
				{Id: serviceID, Protocol: controlv1.ServiceProtocolHTTP, Endpoint: &controlv1.ServiceEndpoint{Hostname: hostname, Port: 443, Public: true}},
			}})
		default:
			t.Errorf("unexpected control request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer control.Close()

	transport := visitor.Client().Transport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		switch address {
		case hostname + ":443":
			address = visitor.Listener.Addr().String()
		case control.Listener.Addr().String():
		default:
			return nil, fmt.Errorf("unexpected dial address: %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	previous := http.DefaultTransport
	http.DefaultTransport = transport
	defer func() {
		http.DefaultTransport = previous
		transport.CloseIdleConnections()
	}()

	stateDir := filepath.Join(t.TempDir(), "state")
	state, err := clientstate.Open(t.Context(), stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	profile, err := state.Server(t.Context(), control.URL)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := profile.SaveControlSession(t.Context(), clientstate.ControlSession{
		SessionID: "cs_0123456789abcdefghijkl", AccessToken: access.String(), RefreshToken: refresh.String(),
		AccessExpiresAt: now.Add(time.Hour), RefreshExpiresAt: now.Add(24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	for _, target := range []string{hostname, serviceID} {
		out.Reset()
		args := []string{"--config", "missing.yml", "ping", target, "--server", control.URL, "--state-dir", stateDir}
		if err := run(t.Context(), args, &out, io.Discard); err != nil || out.String() != "HTTP 204 No Content  https://"+hostname+"\n" {
			t.Fatalf("ping %s = %q, %v", target, &out, err)
		}
		if target == hostname && controlCalls.Load() != 0 {
			t.Fatal("literal hostname reached control")
		}
	}
	if controlCalls.Load() != 3 || visitorCalls.Load() != 2 {
		t.Fatalf("control calls = %d, visitor calls = %d", controlCalls.Load(), visitorCalls.Load())
	}
	out.Reset()
	if err := run(t.Context(), []string{"ping", privateID, "--server", control.URL, "--state-dir", stateDir}, &out, io.Discard); err == nil || out.Len() != 0 || visitorCalls.Load() != 2 {
		t.Fatalf("private service produced a public probe: %q, %v", &out, err)
	}
}

func TestPingReportsHTTPResultAndExitsZeroOnAppErrors(t *testing.T) {
	for _, tt := range []struct {
		status int
		code   string
		want   string
	}{
		{200, "", "HTTP 200 OK"},
		{302, "", "HTTP 302 Found (redirect not followed)"},
		{304, "", "HTTP 304 Not Modified"},
		{404, "", "HTTP 404 Not Found"},
		{500, "", "HTTP 500 Internal Server Error"},
		{503, "", "HTTP 503 Service Unavailable"},
		{599, "", "HTTP 599"},
		{403, "TNL_IP_POLICY_DENIED", "HTTP 403 Forbidden (tnl: TNL_IP_POLICY_DENIED)"},
	} {
		t.Run(tt.want, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(publisherapp.DiagnosticHeader, tt.code)
				w.WriteHeader(tt.status)
			}))
			defer server.Close()
			var out bytes.Buffer
			flags := pingCommand{URL: server.URL, Output: statusOutputHuman}
			err := runPing(t.Context(), flags, &out, nil)
			if (err != nil) != (tt.code != "") || out.String() != tt.want+"  "+server.URL+"\n" {
				t.Fatalf("ping = %q, %v", &out, err)
			}
			if err != nil {
				var diag bytes.Buffer
				writeCommandError(&diag, err)
				if !strings.Contains(diag.String(), "IP address") || !strings.Contains(diag.String(), "TNL_CLIENT_TUNNEL_UNAVAILABLE") {
					t.Fatalf("ping denial = %q", &diag)
				}
			}
			if tt.status == http.StatusNotModified {
				flags.Output = statusOutputJSON
				out.Reset()
				if err := runPing(t.Context(), flags, &out, nil); err != nil || !strings.Contains(out.String(), `"state":"redirected (not followed)"`) {
					t.Fatalf("304 machine result = %q, %v", &out, err)
				}
			}
		})
	}
}

func TestPingHTTPExpectationKeepsObservation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthy":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()
	for _, tt := range []struct {
		path     string
		status   int
		want     string
		wantFail bool
	}{
		{"/healthy", http.StatusNoContent, "HTTP 204 No Content", false},
		{"/starting", http.StatusServiceUnavailable, "HTTP 503 Service Unavailable", true},
	} {
		for _, format := range []string{"human", "json"} {
			t.Run(tt.path+" "+format, func(t *testing.T) {
				var out, diag bytes.Buffer
				address := server.URL + tt.path
				err := run(t.Context(), []string{"ping", address, "--expect", "2xx", "--output", format}, &out, &diag)
				if (err != nil) != tt.wantFail {
					t.Fatalf("observation=%q, err=%v", &out, err)
				}
				if tt.wantFail {
					writeCommandError(&diag, err)
					want := "expected an HTTP 2xx response"
					if format == "json" {
						want = "TNL_CLIENT_TUNNEL_UNAVAILABLE"
					}
					if !strings.Contains(diag.String(), want) {
						t.Fatalf("expectation error = %q", &diag)
					}
				}
				if format == "human" {
					if got := out.String(); got != tt.want+"  "+address+"\n" {
						t.Fatalf("observation = %q", got)
					}
				} else {
					var result publisherapp.PingResult
					if err := json.Unmarshal(out.Bytes(), &result); err != nil || result.Status != tt.status || result.Address != address {
						t.Fatalf("observation=%q, err=%v", &out, err)
					}
				}
			})
		}
	}
}

func TestPingTCPAddressAndProtocolURLOnlyCheckTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	address := listener.Addr().String()
	if err := run(t.Context(), []string{"ping", "postgresql://" + address + "/orders?hostaddr=127.0.0.9&password=secret"}, &out, io.Discard); err != nil ||
		out.String() != "TCP connected  postgresql://"+address+"\n" {
		t.Fatalf("ping used or echoed database options: %q, %v", &out, err)
	}
	defer listener.Close()
	for _, address := range []string{listener.Addr().String(), "postgres://" + listener.Addr().String()} {
		var out, diag bytes.Buffer
		if err := run(t.Context(), []string{"ping", address}, &out, &diag); err != nil || out.String() != "TCP connected  "+address+"\n" {
			t.Fatalf("ping = %q, %v", &out, err)
		}
		out.Reset()
		if err := run(t.Context(), []string{"ping", address, "--output", "json"}, &out, &diag); err != nil {
			t.Fatal(err)
		}
		var result publisherapp.PingResult
		if err := json.Unmarshal(out.Bytes(), &result); err != nil || result.State != "tcp connected" || result.Protocol != "tcp" || result.Address != address || result.Status != 0 {
			t.Fatalf("observation=%q, err=%v", &out, err)
		}
		out.Reset()
		err := run(t.Context(), []string{"ping", address, "--expect", "2xx"}, &out, &diag)
		if err == nil || out.Len() != 0 {
			t.Fatalf("TCP expectation = %q, %v", &out, err)
		}
		writeCommandError(&diag, err)
		if !strings.Contains(diag.String(), "--expect 2xx requires an HTTP or HTTPS check") {
			t.Fatalf("TCP expectation error = %q", &diag)
		}
	}
}

func TestPingConnectionFailureExplainsTheVisitorCheck(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	server.Close()
	var out, diag bytes.Buffer
	err := runPing(t.Context(), pingCommand{URL: server.URL}, &out, nil)
	if err == nil || out.String() != "No HTTP response  "+server.URL+"\n" {
		t.Fatalf("ping = %q, %v", &out, err)
	}
	writeCommandError(&diag, err)
	if !strings.Contains(diag.String(), "connection or TLS verification failed") {
		t.Fatalf("ping error = %q", &diag)
	}
}

func TestPingInvalidURLShowsExpectedInput(t *testing.T) {
	var out, diag bytes.Buffer
	err := runPing(t.Context(), pingCommand{URL: "https://user:secret@app.example"}, &out, nil)
	if err == nil || out.Len() != 0 {
		t.Fatalf("ping = %q, %v", &out, err)
	}
	writeCommandError(&diag, err)
	text := strings.Join(strings.Fields(diag.String()), " ")
	if !strings.Contains(text, "provide a hostname, a full HTTP or HTTPS URL, a TCP address, or an exact service ID") || !strings.Contains(text, "TNL_CLIENT_INVALID_COMMAND") || strings.Contains(text, "secret") {
		t.Fatalf("ping error = %q", &diag)
	}
}
