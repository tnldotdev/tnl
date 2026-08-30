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

func TestNormalizeTarget(t *testing.T) {
	accepted := map[string]string{
		"3000":                           "http://127.0.0.1:3000",
		"03000":                          "http://127.0.0.1:3000",
		"http://127.0.0.1:3000":          "http://127.0.0.1:3000",
		"http://127.0.0.2:03000":         "http://127.0.0.2:3000",
		"http://[::1]:3000":              "http://[::1]:3000",
		"http://[0:0:0:0:0:0:0:1]:03000": "http://[::1]:3000",
		"HTTP://[0:0:0:0:0:0:0:1]:3000":  "http://[::1]:3000",
	}
	for target, want := range accepted {
		t.Run(target, func(t *testing.T) {
			got, err := NormalizeTarget(target)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("NormalizeTarget(%q) = %q, want %q", target, got, want)
			}
		})
	}

	rejected := []string{
		"", "0", "65536", "+3000", "-3000", "30x00", "127.0.0.1:3000",
		" 3000", "3000 ", "3 000", "\t3000",
		"http://localhost:3000", "http://192.0.2.1:3000", "http://[::2]:3000",
		"https://127.0.0.1:3000", "http://127.0.0.1", "http://127.0.0.1:0",
		"http://127.0.0.1:65536", "http://127.0.0.1:bad",
		"http://127.0.0.1:3000/", "http://127.0.0.1:3000/path",
		"http://user@127.0.0.1:3000", "http://127.0.0.1:3000?query",
		"http://127.0.0.1:3000#fragment",
	}
	for _, target := range rejected {
		t.Run(target, func(t *testing.T) {
			if got, err := NormalizeTarget(target); err == nil {
				t.Fatalf("NormalizeTarget(%q) = %q, want error", target, got)
			}
		})
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
