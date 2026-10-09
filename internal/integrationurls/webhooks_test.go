package integrationurls

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/webhookips"
)

func TestWebhookFanoutRequiresAllReceiversAndPreservesSignatureInputs(t *testing.T) {
	state, _ := callbackState(t)
	const body = "{\"event\":\"paid\", \"amount\":300}\n"
	var failed atomic.Bool
	var calls atomic.Int32
	definition := config.Webhook{Service: "api", Path: "/api/webhooks/stripe", Provider: "stripe", SourceIPs: []string{"192.0.2.0/24"}}
	encoded, _, err := DefinitionBytes(definition)
	if err != nil {
		t.Fatal(err)
	}
	for _, hostname := range []string{"main.example.test", "feature.example.test"} {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			data, err := io.ReadAll(request.Body)
			mac := hmac.New(sha256.New, []byte("test-key"))
			_, _ = mac.Write(data)
			if err != nil || string(data) != body || request.Header.Get("Stripe-Signature") != hex.EncodeToString(mac.Sum(nil)) ||
				request.Host != "hooks.project.example.test" || request.URL.RequestURI() != "/api/webhooks/stripe?value=a%2Fb&value=a+b" ||
				request.Header.Get("X-Forwarded-For") != "192.0.2.1" || request.Header.Get("X-Forwarded-Proto") != "https" ||
				request.Header.Get("X-Original-URL") != "" {
				t.Errorf("signed webhook changed: %s %q %v", request.URL.RequestURI(), string(data), err)
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			calls.Add(1)
			if failed.Load() && hostname == "feature.example.test" {
				response.WriteHeader(http.StatusInternalServerError)
			} else {
				response.WriteHeader(http.StatusNoContent)
			}
		}))
		t.Cleanup(server.Close)
		tunnel, _ := readyTunnel(t, state, server.URL, hostname)
		if err := tunnel.RegisterWebhookEndpoint(t.Context(), "stripe", encoded); err != nil {
			t.Fatal(err)
		}
	}
	handler, _, err := NewWebhooks(t.Context(), state, testServer, testOAuthHost, "hooks.project.example.test", map[string]config.Webhook{"stripe": definition}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var received atomic.Int32
	handler.OnReceiverResponse = func(mode string) {
		if mode != "fanout" {
			t.Errorf("delivery mode = %q", mode)
		}
		received.Add(1)
	}
	send := func(ip, method, path string, want int) {
		t.Helper()
		request := httptest.NewRequest(method, "https://hooks.project.example.test"+path, strings.NewReader(body))
		request.RemoteAddr = ip + ":1234"
		mac := hmac.New(sha256.New, []byte("test-key"))
		_, _ = mac.Write([]byte(body))
		request.Header.Set("Stripe-Signature", hex.EncodeToString(mac.Sum(nil)))
		request.Header.Set("X-Forwarded-For", "203.0.113.1")
		request.Header.Set("X-Original-URL", "/admin")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != want {
			t.Fatalf("%s %s from %s: got %d want %d", method, path, ip, response.Code, want)
		}
	}
	for _, path := range []string{"/admin", "/api/webhooks/github", "/api/webhooks/%73tripe", "/api/webhooks/stripe/", "/api/webhooks/stripe/../admin", "//api/webhooks/stripe"} {
		send("192.0.2.1", http.MethodPost, path, http.StatusForbidden)
	}
	send("198.51.100.1", http.MethodPost, "/api/webhooks/stripe", http.StatusForbidden)
	send("192.0.2.1", http.MethodGet, "/api/webhooks/stripe", http.StatusForbidden)
	if calls.Load() != 0 || received.Load() != 0 {
		t.Fatal("denied requests reached a worktree")
	}
	send("192.0.2.1", http.MethodPost, "/api/webhooks/stripe?value=a%2Fb&value=a+b", http.StatusOK)
	if calls.Load() != 2 || received.Load() != 2 {
		t.Fatalf("fanout delivered %d requests, observed %d responses", calls.Load(), received.Load())
	}
	failed.Store(true)
	send("192.0.2.1", http.MethodPost, "/api/webhooks/stripe?value=a%2Fb&value=a+b", http.StatusBadGateway)
	if calls.Load() != 4 || received.Load() != 4 {
		t.Fatalf("failure skipped another receiver: %d calls, %d responses", calls.Load(), received.Load())
	}
}

type untrustedBody struct{ reads atomic.Int32 }

func (b *untrustedBody) Read([]byte) (int, error) { b.reads.Add(1); return 0, io.EOF }
func (*untrustedBody) Close() error               { return nil }

func TestWebhookPathAndIPAdmissionPrecedesBodyRead(t *testing.T) {
	state, _ := callbackState(t)
	handler, _, err := NewWebhooks(t.Context(), state, testServer, testOAuthHost, "hooks.project.example.test", map[string]config.Webhook{
		"stripe": {Service: "api", Path: "/hooks/stripe", Provider: "stripe", SourceIPs: []string{"192.0.2.0/24"}},
		"github": {Service: "api", Path: "/hooks/github", Provider: "github", SourceIPs: []string{"198.51.100.0/24"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := &untrustedBody{}
	request := httptest.NewRequest(http.MethodPost, "https://hooks.project.example.test/hooks/github", nil)
	request.RemoteAddr = "192.0.2.1:1234"
	request.Body = body
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || body.reads.Load() != 0 {
		t.Fatal("Stripe-like source read or forwarded a different endpoint body")
	}
}

func TestWebhookWildcardSourceDoesNotBroadenAnotherEndpoint(t *testing.T) {
	state, _ := callbackState(t)
	handler, ingressIPs, err := NewWebhooks(t.Context(), state, testServer, testOAuthHost, "hooks.project.example.test", map[string]config.Webhook{
		"open":       {Service: "api", Path: "/hooks/open", Provider: "custom"},
		"restricted": {Service: "api", Path: "/hooks/restricted", Provider: "stripe", SourceIPs: []string{"192.0.2.0/24"}},
	}, nil)
	if err != nil || len(ingressIPs) != 0 {
		t.Fatalf("wildcard publisher policy = %v, %v", ingressIPs, err)
	}
	body := &untrustedBody{}
	request := httptest.NewRequest(http.MethodPost, "https://hooks.project.example.test/hooks/restricted", nil)
	request.RemoteAddr = "198.51.100.1:1234"
	request.Body = body
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || body.reads.Load() != 0 {
		t.Fatal("wildcard endpoint admitted a visitor to the restricted endpoint")
	}
}

func TestUnavailableCatalogPolicyDoesNotBlockOtherWebhookOrReadFailedBody(t *testing.T) {
	state, _ := callbackState(t)
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	stripe := config.Webhook{Service: "api", Path: "/hooks/stripe", Provider: "stripe", SourceIPs: []string{"192.0.2.0/24"}}
	encoded, _, err := DefinitionBytes(stripe)
	if err != nil {
		t.Fatal(err)
	}
	tunnel, _ := readyTunnel(t, state, target.URL, "main.example.test")
	if err := tunnel.RegisterWebhookEndpoint(t.Context(), "stripe", encoded); err != nil {
		t.Fatal(err)
	}
	handler, ingressIPs, err := newWebhooks(t.Context(), state, testServer, testOAuthHost, "hooks.project.example.test", map[string]config.Webhook{
		"stripe": stripe,
		"github": {Service: "api", Path: "/hooks/github", Provider: "github"},
	}, nil, func(_ context.Context, _ webhookips.Cache, server, name string) (webhookips.Source, error) {
		if server != testServer || name != "github" {
			t.Errorf("unexpected catalog lookup for %s on %s", name, server)
		}
		return webhookips.Source{}, errors.New("catalog unavailable")
	})
	if err != nil || handler == nil {
		t.Fatalf("prepare webhook policies: %v", err)
	}
	if !slices.Equal(ingressIPs, []string{"192.0.2.0/24"}) ||
		handler.PolicyStatus("github") != "unavailable" || handler.PolicyStatus("stripe") != "1 IP ranges" {
		t.Fatalf("partial policy = %v, github=%q, stripe=%q, error=%v", ingressIPs, handler.PolicyStatus("github"), handler.PolicyStatus("stripe"), err)
	}
	stripeRequest := httptest.NewRequest(http.MethodPost, "https://hooks.project.example.test/hooks/stripe", nil)
	stripeRequest.RemoteAddr = "192.0.2.1:1234"
	stripeResponse := httptest.NewRecorder()
	handler.ServeHTTP(stripeResponse, stripeRequest)
	if stripeResponse.Code != http.StatusOK {
		t.Fatalf("ready Stripe endpoint = %d", stripeResponse.Code)
	}
	body := &untrustedBody{}
	githubRequest := httptest.NewRequest(http.MethodPost, "https://hooks.project.example.test/hooks/github", nil)
	githubRequest.RemoteAddr = "192.0.2.1:1234"
	githubRequest.Body = body
	githubResponse := httptest.NewRecorder()
	handler.ServeHTTP(githubResponse, githubRequest)
	if githubResponse.Code != http.StatusServiceUnavailable || body.reads.Load() != 0 {
		t.Fatalf("unavailable provider read request body or admitted visitor: %d, reads=%d", githubResponse.Code, body.reads.Load())
	}
}

func TestWebhookCustomProviderCanUseAnExplicitHTTPMethod(t *testing.T) {
	state, _ := callbackState(t)
	called := make(chan string, 1)
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		called <- request.Method + " " + request.URL.RequestURI()
		response.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	definition := config.Webhook{Service: "api", Path: "/hooks/custom", Provider: "custom", Methods: []string{http.MethodPut}, SourceIPs: []string{"198.51.100.0/24"}}
	encoded, _, err := DefinitionBytes(definition)
	if err != nil {
		t.Fatal(err)
	}
	tunnel, _ := readyTunnel(t, state, target.URL, "custom.example.test")
	if err := tunnel.RegisterWebhookEndpoint(t.Context(), "custom", encoded); err != nil {
		t.Fatal(err)
	}
	handler, prefixes, err := NewWebhooks(t.Context(), state, testServer, testOAuthHost, "hooks.project.example.test", map[string]config.Webhook{"custom": definition}, nil)
	if err != nil || len(prefixes) != 1 || prefixes[0] != "198.51.100.0/24" {
		t.Fatalf("custom source policy = %v, %v", prefixes, err)
	}
	request := httptest.NewRequest(http.MethodPut, "https://hooks.project.example.test/hooks/custom?batch=one", strings.NewReader("signed-body"))
	request.RemoteAddr = "198.51.100.1:1234"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("custom provider delivery = %d", response.Code)
	}
	select {
	case got := <-called:
		if got != "PUT /hooks/custom?batch=one" {
			t.Fatalf("custom provider request = %q", got)
		}
	default:
		t.Fatal("custom provider request did not reach its service")
	}
}

func TestWebhookVerificationReturnsOnlyMatchingResponses(t *testing.T) {
	state, _ := callbackState(t)
	definition := config.Webhook{Service: "api", Path: "/hooks/verify", Provider: "custom", Methods: []string{"GET"}}
	encoded, _, err := DefinitionBytes(definition)
	if err != nil {
		t.Fatal(err)
	}
	var mismatch atomic.Bool
	for index, host := range []string{"main.example.test", "feature.example.test"} {
		server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			if index == 1 && mismatch.Load() {
				_, _ = io.WriteString(response, "wrong")
			} else {
				_, _ = io.WriteString(response, "challenge")
			}
		}))
		t.Cleanup(server.Close)
		tunnel, _ := readyTunnel(t, state, server.URL, host)
		if err := tunnel.RegisterWebhookEndpoint(t.Context(), "verify", encoded); err != nil {
			t.Fatal(err)
		}
	}
	handler, _, err := NewWebhooks(t.Context(), state, testServer, testOAuthHost, "hooks.project.example.test", map[string]config.Webhook{"verify": definition}, nil)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://hooks.project.example.test/hooks/verify", nil)
	request.RemoteAddr = "192.0.2.1:1234"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "challenge" {
		t.Fatalf("verification: %d %q", response.Code, response.Body.String())
	}
	mismatch.Store(true)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("mismatched verification succeeded: %d", response.Code)
	}
}
