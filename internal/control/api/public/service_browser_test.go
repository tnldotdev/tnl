package public

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type serviceBrowserHandoffStore struct {
	ServiceHTTPStore
	source     controlstate.VisitorTokenSource
	auth       controlstate.ServiceHTTPRun
	permission error
	identity   error
	redeemed   bool
}

func (s *serviceBrowserHandoffStore) RedeemServiceBrowserHandoff(_ context.Context, auth controlstate.ServiceHTTPRun, _ string, now time.Time) (controlv1.BrowserHandoffResponse, error) {
	s.redeemed, s.auth = true, auth
	return controlv1.BrowserHandoffResponse{CookieSecret: strings.Repeat("B", 43), ReturnPath: "/", ExpiresAt: now.Add(time.Hour)}, nil
}

func (s *serviceBrowserHandoffStore) ServiceBrowserSession(context.Context, controlstate.ServiceHTTPRun, string, bool, time.Time) (controlstate.VisitorPermission, error) {
	return controlstate.VisitorPermission{Authenticated: true, IdentityID: "person", DisplayName: "Sam"}, s.identity
}

func (s *serviceBrowserHandoffStore) IssueVisitorToken(_ context.Context, _ string, scope visitorscope.Scope, source controlstate.VisitorTokenSource, now time.Time) (controlstate.IssuedVisitorToken, error) {
	s.source = source
	return controlstate.IssuedVisitorToken{Permission: visitortoken.Permission{Scope: scope, ExpiresAt: now.Add(time.Minute)}}, s.permission
}

func TestServiceBrowserHandoffKeepsIdentitySeparateFromVisitorPermission(t *testing.T) {
	service, run := "svc_"+strings.Repeat("A", 22), "srun_"+strings.Repeat("A", 22)
	share := "shr_" + strings.Repeat("A", 22)
	for _, test := range []struct {
		name       string
		extra      string
		permission error
		identity   error
		status     int
		token      bool
		share      bool
	}{
		{"identity only", "", controlstate.ErrVisitorPermission, nil, 200, false, false},
		{"current browser permission", "", nil, nil, 200, true, false},
		{"outside reviewer share", `,"share_id":"` + share + `","share_cookie_secret":"` + strings.Repeat("C", 43) + `"`, nil, nil, 200, true, true},
		{"revoked browser identity", "", controlstate.ErrVisitorPermission, controlstate.ErrVisitorSignIn, 401, false, false},
		{"signing unavailable", "", controlstate.ErrVisitorSigningKey, nil, 503, false, false},
		{"incomplete share proof", `,"share_id":"` + share + `"`, nil, nil, 400, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &serviceBrowserHandoffStore{permission: test.permission, identity: test.identity}
			h := &handler{dependencies: Stores{ServiceHTTP: store, VisitorTokens: store}}
			body := `{"run_number":"7","secret":"` + strings.Repeat("A", 43) + `"` + test.extra + `}`
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
			request.Header.Set("Authorization", "Bearer "+strings.Repeat("D", 43))
			response := httptest.NewRecorder()
			h.RedeemServiceBrowserHandoff(response, request, service, run)
			if response.Code != test.status {
				t.Fatalf("handoff status = %d, want %d: %s", response.Code, test.status, response.Body)
			}
			if test.status != 200 {
				if test.status == 400 && store.redeemed {
					t.Fatal("incomplete share proof consumed the browser handoff")
				}
				return
			}
			var result controlv1.BrowserHandoffResponse
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.CookieSecret == "" || (result.Permission != nil) != test.token ||
				store.auth.Subject.ID != service || store.auth.RunID != run || store.auth.Number != 7 {
				t.Fatal("handoff lost identity, permission, or exact service run")
			}
			if test.share {
				source, ok := store.source.(controlstate.ShareSessionTokenSource)
				if !ok || source.ShareID != share || source.Secret != strings.Repeat("C", 43) || source.RunID != run {
					t.Fatal("outside reviewer handoff did not use its independent share session")
				}
			} else if _, ok := store.source.(controlstate.BrowserSessionTokenSource); !ok {
				t.Fatal("browser handoff invented another visitor source")
			}
		})
	}
}
