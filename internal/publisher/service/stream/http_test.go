package stream

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
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
			DenyHTTP(response, test.status)
			if response.Code != test.status || response.Header().Get("Connection") != "close" {
				t.Fatalf("denial = %d, headers = %v", response.Code, response.Header())
			}
		})
	}
}
