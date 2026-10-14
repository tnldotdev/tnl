package controlapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
)

type adminBrowserFlowStub struct {
	BrowserAccessStore
	refresh credentials.RefreshToken
}

func (s *adminBrowserFlowStub) IssueAdminBrowserHandoff(_ context.Context, _ credentials.AccessToken, refresh credentials.RefreshToken,
	_ string, _ int64, _, _ time.Duration, _ time.Time,
) (controlstate.BrowserHandoff, string, error) {
	s.refresh = refresh
	return controlstate.BrowserHandoff{Token: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, "web.example.test", nil
}

func TestBuiltinAdministratorBrowserHandoffDoesNotEchoRefreshCredential(t *testing.T) {
	store := &adminBrowserFlowStub{}
	authorizer := &recordingAuthorizer{principal: publicURLReadPrincipal{identityID: "admin", administrator: true}}
	h := &handler{config: Config{LoginToken: testLoginToken, ServerDomain: "example.test", ControlURL: "https://control.example.test", AccessTokenLifetime: time.Hour,
		RefreshTokenLifetime: 24 * time.Hour}, authorizer: authorizer, browserAccess: store}
	request := func() *http.Request {
		value := httptest.NewRequest(http.MethodPost, "/v1/browser/admin-handoff", strings.NewReader(`{"public_url_id":"url_current","refresh_token":"private-refresh"}`))
		value.Header.Set("Authorization", "Bearer access-token")
		return value
	}
	response := httptest.NewRecorder()
	h.CreateAdminBrowserHandoff(response, request())
	if response.Code != http.StatusCreated || store.refresh != "private-refresh" ||
		!strings.Contains(response.Body.String(), "https://web.example.test/__tnl/team/handoff/") ||
		strings.Contains(response.Body.String(), "private-refresh") || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("administrator handoff = %d %s", response.Code, response.Body.String())
	}
	authorizer.principal.administrator = false
	store.refresh = ""
	denied := httptest.NewRecorder()
	h.CreateAdminBrowserHandoff(denied, request())
	if denied.Code != http.StatusNotFound || store.refresh != "" {
		t.Fatalf("ordinary member got administrator handoff: %d %s", denied.Code, denied.Body.String())
	}
}
