package stream

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestHTTPDecisionStatusKeepsDenialSeparateFromOutage(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		status int
	}{
		{"no permission", nil, http.StatusForbidden},
		{"invalid token", visitortoken.ErrToken, http.StatusForbidden},
		{"wrong binding", visitortoken.ErrBinding, http.StatusForbidden},
		{"revoked", clientcontrol.ErrUnauthenticated, http.StatusForbidden},
		{"not found", clientcontrol.ErrNotFound, http.StatusForbidden},
		{"stale", clientcontrol.ErrStatusConflict, http.StatusForbidden},
		{"forbidden problem", &clientcontrol.ProblemError{Status: http.StatusForbidden}, http.StatusForbidden},
		{"unavailable", clientcontrol.ErrUnavailable, http.StatusServiceUnavailable},
		{"unexpected", errors.New("fixture failure"), http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := HTTPDecisionStatus(test.err); got != test.status {
				t.Fatalf("status = %d, want %d", got, test.status)
			}
			response := httptest.NewRecorder()
			DenyHTTP(response, httptest.NewRequest(http.MethodGet, "https://service.example.test", nil), test.status)
			if response.Code != test.status || response.Header().Get("Connection") != "close" {
				t.Fatalf("denial = %d, headers = %v", response.Code, response.Header())
			}
		})
	}
}

func TestDenyHTTPUsesDiagnosticResponse(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		code   diagnostic.Code
	}{
		{"denied", http.StatusForbidden, diagnostic.VisitorAccessDenied},
		{"misdirected", http.StatusMisdirectedRequest, diagnostic.RequestMisdirected},
	} {
		for _, accept := range []string{"text/plain", "text/html", "text/html;q=0, text/plain"} {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				t.Run(test.name+"/"+accept+"/"+method, func(t *testing.T) {
					request := httptest.NewRequest(method, "https://service.example.test", nil)
					request.Header.Set("Accept", accept)
					want := httptest.NewRecorder()
					diagnostic.WriteHTTP(want, request, test.code, "")
					got := httptest.NewRecorder()
					DenyHTTP(got, request, test.status)
					if got.Code != test.status || got.Header().Get("Connection") != "close" {
						t.Fatalf("denial = %d, headers = %v", got.Code, got.Header())
					}
					for key, values := range want.Header() {
						if strings.Join(got.Header().Values(key), ",") != strings.Join(values, ",") {
							t.Errorf("%s = %q, want %q", key, got.Header().Values(key), values)
						}
					}
					if got.Body.String() != want.Body.String() {
						t.Fatal("denial did not use the diagnostic response body")
					}
					if got.Header().Get("Tnl-Error-Code") != string(test.code) || got.Header().Get("Cache-Control") != "no-store" ||
						got.Header().Get("Vary") != "Accept" || got.Header().Get("X-Content-Type-Options") != "nosniff" {
						t.Fatal("denial lost diagnostic or cache headers", got.Header())
					}
					length, err := strconv.Atoi(got.Header().Get("Content-Length"))
					if err != nil || length == 0 {
						t.Fatal("denial has no representation length", got.Header())
					}
					if method == http.MethodHead {
						if got.Body.Len() != 0 {
							t.Fatal("HEAD denial wrote a body")
						}
						return
					}
					if length != got.Body.Len() || !strings.Contains(got.Body.String(), diagnostic.HelpURL(test.code, "")) {
						t.Fatal("denial lost its complete body or help URL", got.Body.String())
					}
					contentType := "text/plain; charset=utf-8"
					if accept == "text/html" {
						contentType = "text/html; charset=utf-8"
					}
					if got.Header().Get("Content-Type") != contentType {
						t.Fatal("denial did not negotiate its representation", got.Header())
					}
				})
			}
		}
	}
}
