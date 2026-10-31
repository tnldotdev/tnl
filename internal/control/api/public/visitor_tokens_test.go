package public

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

func TestVisitorTokenSourceRejectsMixedUnknownAndIncompleteVariants(t *testing.T) {
	for _, source := range []string{
		`null`, `[]`, `{}`, `{"kind":"publisher"}`,
		`{"kind":"control_session","secret":"ignored"}`,
		`{"kind":"control_session","preview_id":"bad"}`,
		`{"kind":"device"}`,
		`{"kind":"device","device_id":"vdev_` + strings.Repeat("A", 22) + `","credential":"ignored"}`,
		`{"kind":"workload"}`,
		`{"kind":"share","share_id":"shr_` + strings.Repeat("A", 22) + `"}`,
		`{"kind":"browser_session","secret":"` + strings.Repeat("A", 43) + `","identity_id":"ignored"}`,
		`{"kind":"grant","credential":"` + strings.Repeat("A", 129) + `"}`,
	} {
		if _, _, err := parseVisitorTokenSource(json.RawMessage(source)); err == nil {
			t.Fatal("accepted an ambiguous visitor source")
		}
	}
	for source, human := range map[string]bool{
		`{"kind":"control_session"}`: true,
		`{"kind":"device","device_id":"vdev_` + strings.Repeat("A", 22) + `"}`:                                         true,
		`{"kind":"browser_session","secret":"` + strings.Repeat("A", 43) + `"}`:                                        false,
		`{"kind":"workload","credential":"wlc_` + strings.Repeat("A", 43) + `"}`:                                       false,
		`{"kind":"share","share_id":"shr_` + strings.Repeat("A", 22) + `","secret":"` + strings.Repeat("B", 43) + `"}`: false,
	} {
		parsed, needsHuman, err := parseVisitorTokenSource(json.RawMessage(source))
		if err != nil || parsed == nil || needsHuman != human {
			t.Fatal("incorrect source authentication boundary", err)
		}
	}
}

type serviceBrowserTokenStore struct {
	PublicURLStore
	refreshed, issued bool
	err               error
}

func (s *serviceBrowserTokenStore) RefreshServiceBrowserSession(context.Context, string, string, time.Time, func(context.Context, string) (controlstate.BrowserTokenRotation, error)) (controlstate.BrowserAccessSession, error) {
	s.refreshed = true
	return controlstate.BrowserAccessSession{}, s.err
}

func (s *serviceBrowserTokenStore) IssueVisitorToken(context.Context, string, visitorscope.Scope, controlstate.VisitorTokenSource, time.Time) (controlstate.IssuedVisitorToken, error) {
	s.issued = true
	if !s.refreshed {
		return controlstate.IssuedVisitorToken{}, controlstate.ErrVisitorPermission
	}
	return controlstate.IssuedVisitorToken{}, nil
}

func TestVisitorTokenRefreshesServiceBrowserBeforeIssuingPermission(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		status int
	}{
		{"current session", nil, http.StatusOK},
		{"expired session", controlstate.ErrVisitorPermission, http.StatusForbidden},
		{"authority outage", clientauthority.ErrUnavailable, http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &serviceBrowserTokenStore{err: test.err}
			h := &handler{store: store}
			request := httptest.NewRequest(http.MethodPost, "/v1/visitor-tokens", strings.NewReader(`{"resource":{"kind":"service","id":"svc_`+strings.Repeat("A", 22)+`"},"source":{"kind":"browser_session","secret":"`+strings.Repeat("B", 43)+`"}}`))
			response := httptest.NewRecorder()
			h.IssueVisitorToken(response, request)
			if response.Code != test.status || !store.refreshed || store.issued != (test.err == nil) {
				t.Fatal("service permission did not follow browser refresh", response.Code, store.refreshed, store.issued)
			}
		})
	}
}
