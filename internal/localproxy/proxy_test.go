package localproxy

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxyForwardsOnlyExactTrustedRequests(t *testing.T) {
	type received struct {
		Host      string
		Forwarded string
		RealIP    string
	}
	requests := make(chan received, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests <- received{
			Host: request.Host, Forwarded: request.Header.Get("X-Forwarded-For"), RealIP: request.Header.Get("X-Real-IP"),
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	handler, err := New(upstream.URL, "route.example")
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/test", nil)
	request.Host = "route.example"
	request.RemoteAddr = "192.0.2.10:1234"
	request.TLS = &tls.ConnectionState{ServerName: "route.example"}
	request.Header.Set("Forwarded", "for=attacker")
	request.Header.Set("X-Forwarded-For", "198.51.100.1")
	request.Header.Set("X-Real-IP", "198.51.100.1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	got := <-requests
	if got.Host != "route.example" || got.Forwarded != "192.0.2.10" || got.RealIP != "" {
		t.Fatalf("upstream request = %#v", got)
	}

	for name, mutate := range map[string]func(*http.Request){
		"wrong host": func(request *http.Request) { request.Host = "other.example" },
		"wrong SNI":  func(request *http.Request) { request.TLS.ServerName = "other.example" },
		"CONNECT":    func(request *http.Request) { request.Method = http.MethodConnect },
		"absolute": func(request *http.Request) {
			request.RequestURI = "http://127.0.0.1/private"
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/test", nil)
			request.Host = "route.example"
			request.TLS = &tls.ConnectionState{ServerName: "route.example"}
			mutate(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d", response.Code)
			}
		})
	}
}

func TestTargetMustBeLiteralLoopbackHTTP(t *testing.T) {
	for _, target := range []string{
		"http://localhost:3000", "http://192.0.2.1:3000", "https://127.0.0.1:3000",
		"http://127.0.0.1", "http://127.0.0.1:3000/path", "http://user@127.0.0.1:3000",
	} {
		if _, err := New(target, "route.example"); err == nil {
			t.Errorf("New(%q) succeeded", target)
		}
	}
}

func TestPreflightRequiresAvailableTarget(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if err := Preflight(context.Background(), upstream.URL); err != nil {
		t.Fatal(err)
	}
	upstream.Close()
	if err := Preflight(context.Background(), upstream.URL); err == nil {
		t.Fatal("Preflight accepted unavailable target")
	}
}
