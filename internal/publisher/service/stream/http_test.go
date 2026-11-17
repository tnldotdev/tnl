package stream

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"syscall"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
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
		{"unavailable policy", visitortoken.ErrPolicy, http.StatusServiceUnavailable},
		{"unavailable verification key", visitortoken.ErrKey, http.StatusServiceUnavailable},
		{"denied bind", diagnostic.Wrap(diagnostic.VisitorAccessDenied, visitortoken.ErrPolicy), http.StatusForbidden},
		{"canceled bind", diagnostic.Wrap(diagnostic.VisitorAccessDenied, context.Canceled), http.StatusForbidden},
		{"unexpected", errors.New("fixture failure"), http.StatusInternalServerError},
		{"unavailable and fault", errors.Join(clientcontrol.ErrUnavailable, errors.New("private cleanup fault")), http.StatusInternalServerError},
		{"denial and fault", errors.Join(visitortoken.ErrToken, errors.New("private cleanup fault")), http.StatusInternalServerError},
		{"denied bind and fault", diagnostic.Wrap(diagnostic.VisitorAccessDenied, errors.Join(visitortoken.ErrPolicy, errors.New("private cleanup fault"))), http.StatusInternalServerError},
		{"cancellation and fault", errors.Join(context.Canceled, errors.New("private cleanup fault")), http.StatusInternalServerError},
		{"internal problem", &clientcontrol.ProblemError{Status: http.StatusInternalServerError}, http.StatusInternalServerError},
		{"network outage", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, http.StatusServiceUnavailable},
		{"network and independent fault", &net.OpError{Op: "read", Net: "tcp", Err: errors.Join(syscall.ECONNRESET, errors.New("private fault"))}, http.StatusInternalServerError},
		{"known unavailable problem", &clientcontrol.ProblemError{Status: 503, Problem: controlv1.Problem{Code: controlv1.Unavailable}}, http.StatusServiceUnavailable},
		{"unknown unavailable problem", &clientcontrol.ProblemError{Status: 503}, http.StatusInternalServerError},
		{"invalid upstream problem", &clientcontrol.ProblemError{Status: 502, Problem: controlv1.Problem{Code: controlv1.Forbidden}}, http.StatusInternalServerError},
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
