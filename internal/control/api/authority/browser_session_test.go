package authority

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
)

type browserSessionStoreStub struct {
	controlAuthenticationStoreStub
	service string
	calls   int
}

func (s *browserSessionStoreStub) IssueControlBrowserHandoff(_ context.Context, access credentials.AccessToken, refresh credentials.RefreshToken, service string, accessLifetime, refreshLifetime time.Duration, _ time.Time) (controlstate.BrowserHandoff, error) {
	s.calls++
	s.service = service
	if access != "parent-access" || refresh != "parent-refresh" || accessLifetime <= 0 || refreshLifetime <= 0 {
		return controlstate.BrowserHandoff{}, controlstate.ErrControlAuthentication
	}
	return controlstate.BrowserHandoff{Token: "one-use", Origin: "https://web.example.test"}, nil
}

func TestBrowserHandoffAcceptsServiceIDAndRejectsRetiredResourceField(t *testing.T) {
	store := &browserSessionStoreStub{}
	handler := testHandler(t, Config{AccessTokenLifetime: time.Hour, RefreshTokenLifetime: 24 * time.Hour}, store)
	for _, test := range []struct {
		body   string
		status int
	}{
		{`{"public_url_id":"url_0123456789abcdefghijkl","refresh_token":"parent-refresh"}`, http.StatusBadRequest},
		{`{"service_id":"svc_0123456789abcdefghijkl","refresh_token":"parent-refresh"}`, http.StatusCreated},
	} {
		request := httptest.NewRequest(http.MethodPost, "/v1/auth/browser-handoff", strings.NewReader(test.body))
		request.Header.Set("Authorization", "Bearer parent-access")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status || strings.Contains(response.Body.String(), "parent-refresh") || strings.Contains(response.Body.String(), "parent-access") {
			t.Fatalf("browser handoff status=%d, expected=%d", response.Code, test.status)
		}
	}
	if store.calls != 1 || store.service != "svc_0123456789abcdefghijkl" {
		t.Fatal("browser handoff did not pass the defining exact service to state")
	}
}
