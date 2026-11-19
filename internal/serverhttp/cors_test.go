package serverhttp

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestCredentialCORSPreflightDoesNotEnterHandlers(t *testing.T) {
	mux := http.NewServeMux()
	router := NewCredentialCORSRouter(mux, map[string]CredentialCORSHeaders{
		"GET /selected/{id}":   {Request: []string{"Authorization"}, Response: []string{"ETag"}},
		"PATCH /selected/{id}": {Request: []string{"Authorization", "Content-Type", "If-Match"}, Response: []string{"ETag"}},
	})
	calls := 0
	for _, pattern := range []string{"GET /selected/{id}", "PATCH /selected/{id}", "POST /unselected"} {
		router.HandleFunc(pattern, func(http.ResponseWriter, *http.Request) {
			calls++
			t.Fatal("preflight entered the protected handler")
		})
	}
	for _, test := range []struct {
		name, path, origin, method string
		headers                    []string
		allowed                    bool
	}{
		{"bearer", "/selected/value", "https://app.example", "GET", []string{"authorization"}, true},
		{"update", "/selected/value", "https://other.example", "PATCH", []string{"AUTHORIZATION, content-type, IF-MATCH"}, true},
		{"multiple header lines", "/selected/value", "http://localhost:3000", "PATCH", []string{"authorization", "if-match, content-type"}, true},
		{"opaque origin", "/selected/value", "null", "GET", nil, true},
		{"missing origin", "/selected/value", "", "GET", nil, false},
		{"missing method", "/selected/value", "https://app.example", "", nil, false},
		{"wrong method", "/selected/value", "https://app.example", "DELETE", []string{"authorization"}, false},
		{"implicit head", "/selected/value", "https://app.example", "HEAD", []string{"authorization"}, false},
		{"method list", "/selected/value", "https://app.example", "GET, PATCH", nil, false},
		{"wrong method case", "/selected/value", "https://app.example", "get", nil, false},
		{"unlisted header", "/selected/value", "https://app.example", "GET", []string{"authorization, x-tnl-actor-token"}, false},
		{"cookie header", "/selected/value", "https://app.example", "GET", []string{"cookie"}, false},
		{"wildcard header", "/selected/value", "https://app.example", "GET", []string{"*"}, false},
		{"method-specific header", "/selected/value", "https://app.example", "GET", []string{"if-match"}, false},
		{"empty header", "/selected/value", "https://app.example", "GET", []string{"authorization,"}, false},
		{"empty header line", "/selected/value", "https://app.example", "GET", []string{""}, false},
		{"unselected path", "/unselected", "https://app.example", "POST", []string{"content-type"}, false},
		{"extra path", "/selected/value/extra", "https://app.example", "GET", []string{"authorization"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodOptions, test.path, nil)
			if test.origin != "" {
				r.Header.Set("Origin", test.origin)
			}
			if test.method != "" {
				r.Header.Set("Access-Control-Request-Method", test.method)
			}
			r.Header["Access-Control-Request-Headers"] = test.headers
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Header().Get("Access-Control-Allow-Credentials") != "" || w.Header().Get("Access-Control-Expose-Headers") != "" {
				t.Fatal("preflight enabled cookies or exposed response headers")
			}
			if test.allowed {
				if w.Code != http.StatusNoContent || w.Body.Len() != 0 || w.Header().Get("Access-Control-Allow-Origin") != "*" ||
					w.Header().Get("Access-Control-Allow-Methods") != test.method || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("preflight did not grant the exact uncredentialed method", w.Code, w.Header())
				}
				headers := w.Header().Get("Access-Control-Allow-Headers")
				if test.method == "GET" && headers != "Authorization" || test.method == "PATCH" && headers != "Authorization, Content-Type, If-Match" {
					t.Fatal("preflight widened its header grant", headers)
				}
				for _, vary := range []string{"Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers"} {
					if !slices.Contains(w.Header().Values("Vary"), vary) {
						t.Fatal("preflight lost its cache key", vary)
					}
				}
			} else if w.Code < 400 || w.Header().Get("Access-Control-Allow-Origin") != "" || w.Header().Get("Access-Control-Allow-Headers") != "" ||
				w.Header().Get("Access-Control-Allow-Methods") != "" {
				t.Fatal("rejected preflight advertised access", w.Code, w.Header())
			}
		})
	}
	for _, header := range []string{"Origin", "Access-Control-Request-Method"} {
		r := httptest.NewRequest(http.MethodOptions, "/selected/value", nil)
		r.Header.Set("Origin", "https://app.example")
		r.Header.Set("Access-Control-Request-Method", "GET")
		r.Header.Add(header, r.Header.Get(header))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden || w.Body.Len() != 0 || w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("ambiguous preflight accepted", header, w.Code, w.Header())
		}
	}
	if calls != 0 {
		t.Fatal("preflight performed protected work", calls)
	}
}

func TestCredentialCORSOnlyDecoratesExplicitOperations(t *testing.T) {
	mux := http.NewServeMux()
	router := NewCredentialCORSRouter(mux, map[string]CredentialCORSHeaders{
		"GET /selected": {Request: []string{"Authorization"}, Response: []string{"ETag"}},
	})
	for _, pattern := range []string{"GET /selected", "GET /unselected"} {
		router.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			// CORS does not create or replace authentication.
			if r.Header.Get("Authorization") != "Bearer exact-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("ETag", `"7"`)
			w.WriteHeader(http.StatusOK)
		})
	}
	for _, test := range []struct {
		method, path, origin, token string
		status                      int
		cors                        bool
	}{
		{"GET", "/selected", "https://app.example", "Bearer exact-token", 200, true},
		{"GET", "/selected", "null", "Bearer exact-token", 200, true},
		{"GET", "/selected", "https://app.example", "", 401, true},
		{"GET", "/selected", "", "Bearer exact-token", 200, false},
		{"HEAD", "/selected", "https://app.example", "Bearer exact-token", 200, false},
		{"GET", "/unselected", "https://app.example", "Bearer exact-token", 200, false},
		{"DELETE", "/selected", "https://app.example", "Bearer exact-token", 405, false},
	} {
		t.Run(strings.Join([]string{test.method, test.path, test.origin, test.token}, " "), func(t *testing.T) {
			r := httptest.NewRequest(test.method, test.path, nil)
			r.Header.Set("Origin", test.origin)
			r.Header.Set("Authorization", test.token)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != test.status || (w.Header().Get("Access-Control-Allow-Origin") == "*") != test.cors ||
				w.Header().Get("Access-Control-Allow-Credentials") != "" {
				t.Fatal("unexpected CORS or authentication result", w.Code, w.Header())
			}
			if test.cors && (w.Header().Get("Access-Control-Expose-Headers") != "ETag" || w.Header().Get("Cache-Control") != "no-store") {
				t.Fatal("explicit response lost its ETag access or cache policy", w.Header())
			}
		})
	}
}
