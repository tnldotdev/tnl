package public

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
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

func TestVisitorTokenResponseServiceTrustRevision(t *testing.T) {
	issued := controlstate.IssuedVisitorToken{ServiceTrustRevision: 3, Permission: visitortoken.Permission{Scope: visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_test"}}}
	if response := visitorTokenResponse(issued); response.ServiceTrustRevision == nil || *response.ServiceTrustRevision != 3 {
		t.Fatal("service permission omitted its current metadata revision")
	}
	issued.Permission.Scope = visitorscope.Scope{Kind: visitorscope.Kind("public_url"), ID: "url_" + strings.Repeat("A", 22)}
	if issued.Permission.Scope.Valid() {
		t.Fatal("retired public URL resource remained a visitor authority")
	}
}

type serviceBrowserTokenStore struct {
	ServiceHTTPStore
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
			h := &handler{dependencies: Stores{VisitorTokens: store, ServiceHTTP: store}}
			request := httptest.NewRequest(http.MethodPost, "/v1/visitor-tokens", strings.NewReader(`{"resource":{"kind":"service","id":"svc_`+strings.Repeat("A", 22)+`"},"source":{"kind":"browser_session","secret":"`+strings.Repeat("B", 43)+`"}}`))
			response := httptest.NewRecorder()
			h.IssueVisitorToken(response, request)
			if response.Code != test.status || !store.refreshed || store.issued != (test.err == nil) {
				t.Fatal("service permission did not follow browser refresh", response.Code, store.refreshed, store.issued)
			}
		})
	}
}

type guestShareVisitorIssuer struct {
	scope  visitorscope.Scope
	source controlstate.VisitorTokenSource
	calls  int
	deny   bool
}

func (s *guestShareVisitorIssuer) IssueVisitorToken(_ context.Context, _ string, scope visitorscope.Scope, source controlstate.VisitorTokenSource, now time.Time) (controlstate.IssuedVisitorToken, error) {
	s.calls++
	s.scope, s.source = scope, source
	if s.deny {
		return controlstate.IssuedVisitorToken{}, controlstate.ErrVisitorPermission
	}
	return controlstate.IssuedVisitorToken{Token: visitortoken.Token("prepared"),
		ServiceTrustRevision: 3, Permission: visitortoken.Permission{Scope: scope, Hostname: "demo.guest.example", Port: 443,
			VisitorPolicyRevision: 4, ExpiresAt: now.Add(time.Minute)}}, nil
}

func TestGuestShareVisitorTokensUseOrdinaryCurrentSourceAuthority(t *testing.T) {
	for _, kind := range []string{"share", "share_session"} {
		t.Run(kind, func(t *testing.T) {
			service, share := guestAPIID(t, opaqueid.ServicePrefix), guestAPIID(t, opaqueid.SharePrefix)
			store, human := &guestShareVisitorIssuer{}, &guestHumanAuthorizer{}
			trials := guestAPIStore(t)
			trials.lookupErr = errors.New("trial lookup must not be used by share visitors")
			h := &handler{guests: trials, authorizer: human, dependencies: Stores{VisitorTokens: store}}
			body := `{"resource":{"kind":"service","id":"` + service + `"},"source":{"kind":"` + kind +
				`","share_id":"` + share + `","secret":"` + strings.Repeat("B", 43) + `"}}`
			issue := func(withTrialBearer bool) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodPost, "/v1/visitor-tokens", strings.NewReader(body))
				if withTrialBearer {
					r.Header.Set("Authorization", "Bearer guest-token")
				}
				w := httptest.NewRecorder()
				h.IssueVisitorToken(w, r)
				return w
			}
			if w := issue(false); w.Code != 200 || store.calls != 1 || human.reads != 0 || store.scope != (visitorscope.Scope{Kind: visitorscope.Service, ID: service}) {
				t.Fatal("valid guest share was denied or converted to trial/human authentication", w.Code)
			}
			switch source := store.source.(type) {
			case controlstate.ShareTokenSource:
				if kind != "share" || source.ShareID != share {
					t.Fatal("share source changed before current authority was checked")
				}
			case controlstate.ShareSessionTokenSource:
				if kind != "share_session" || source.ShareID != share {
					t.Fatal("share-session source changed before current authority was checked")
				}
			default:
				t.Fatal("share visitor source was replaced")
			}
			store.deny = true
			if w := issue(false); w.Code != 403 || store.calls != 2 {
				t.Fatal("visitor token reused stale share authority", w.Code)
			}
			if w := issue(true); w.Code != 400 || store.calls != 2 || human.reads != 0 {
				t.Fatal("trial bearer broadened a share visitor's authority", w.Code)
			}
		})
	}
}
