package problem

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/browserpage"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestBrowserProblemsRequireOptInAndExplicitHTML(t *testing.T) {
	for _, test := range []struct {
		name, accept string
		optIn, html  bool
	}{
		{"api", "text/html", false, false},
		{"default", "", true, false},
		{"wildcard", "*/*", true, false},
		{"json", "application/json", true, false},
		{"disabled", "text/html;q=0,*/*", true, false},
		{"browser", "text/html", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "https://control.example.test/", nil)
			request.Header.Set("Accept", test.accept)
			response := httptest.NewRecorder()
			var writer http.ResponseWriter = response
			if test.optIn {
				writer = BrowserResponse(writer, request)
			}
			id := WriteWithDetails(writer, http.StatusUnauthorized, "unauthenticated", "sign-in expired", "Open the app again.", "cluster-secret", map[string]any{"unreviewed": "not browser content"})
			if response.Code != http.StatusUnauthorized || !opaqueid.Valid(id, opaqueid.RequestPrefix) ||
				response.Header().Get("Link") != `<https://tnl.dev/p/unauthenticated?case=cluster-secret>; rel="help"` {
				t.Fatal("browser negotiation changed problem identity", response.Header(), id)
			}
			if test.optIn && response.Header().Get("Vary") != "Accept" {
				t.Fatal("negotiated response lacks Vary: Accept")
			}
			if test.html {
				if response.Header().Get("Content-Security-Policy") != browserpage.ContentSecurityPolicy ||
					response.Header().Get("Content-Type") != "text/html; charset=utf-8" ||
					!strings.Contains(response.Body.String(), "<h1>sign-in expired</h1>") ||
					!strings.Contains(response.Body.String(), "<code>"+id+"</code>") ||
					!strings.Contains(response.Body.String(), `<a href="https://tnl.dev/p/unauthenticated?case=cluster-secret">`) ||
					strings.Contains(response.Body.String(), "unreviewed") {
					t.Fatal("HTML problem lost authored fields or rendered arbitrary details")
				}
				return
			}
			var body Problem
			if json.Unmarshal(response.Body.Bytes(), &body) != nil || body.RequestID != id || body.Code != "unauthenticated" ||
				body.Type != URL("unauthenticated") || body.Details["unreviewed"] != "not browser content" ||
				response.Header().Get("Content-Type") != "application/problem+json" {
				t.Fatal("machine problem changed", response.Body.String())
			}
		})
	}
}

func TestBrowserProblemEscapingAndHEAD(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		request := httptest.NewRequest(method, "https://control.example.test/", nil)
		request.Header.Set("Accept", "text/html")
		response := httptest.NewRecorder()
		writer := BrowserResponse(response, request)
		Write(writer, http.StatusForbidden, "forbidden", `<script>bad</script>`, `<img src=x onerror=bad>`, "")
		if response.Code != http.StatusForbidden || strings.Contains(response.Body.String(), "<script>") ||
			strings.Contains(response.Body.String(), "<img") {
			t.Fatal("problem HTML contains executable dynamic content")
		}
		if method == http.MethodHead && response.Body.Len() != 0 {
			t.Fatal("HEAD problem sent a body")
		}
	}
}
