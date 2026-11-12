package httpaccess

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func sessionAllowed(until time.Time) (visitorfixture.HTTPDecision, error) {
	return visitorfixture.HTTPDecision{VisitAllowed: true, ValidUntil: &until}, nil
}
func prepareSessionControl(t *testing.T, control *visitorfixture.HTTPControl) (*Policy, *Tokens) {
	t.Helper()
	control.Init()
	policy, err := PreparePolicy(t.Context(), control, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: visitorfixture.PublicURLID}, "pr_0123456789abcdefghijkl", 1, "fixture-run-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(policy.Close)
	tokens, err := StartTokens(t.Context(), control, policy.Lease(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tokens.Close)
	control.Lease = policy.Lease()
	browser := &Browser{Policy: policy, Tokens: tokens}
	control.Prepare = func(ctx context.Context, source json.RawMessage, response controlv1.VisitorTokenResponse, parent time.Time) error {
		_, err := browser.PrepareToken(ctx, source, response, parent)
		return err
	}
	return policy, tokens
}
func TestBrowserAndShareSessionsReprepareWithoutExpiredVisitorCookie(t *testing.T) {
	for _, name := range []string{"browser", "share", "share without browser login"} {
		share := name != "browser"
		t.Run(name, func(t *testing.T) {
			var revoked atomic.Bool
			var unavailable atomic.Bool
			var deadline atomic.Int64
			deadline.Store(time.Now().Add(45 * time.Second).UnixNano())
			control := &visitorfixture.HTTPControl{Check: func(visitorfixture.HTTPSource) (visitorfixture.HTTPDecision, error) {
				if unavailable.Load() {
					return visitorfixture.HTTPDecision{}, clientcontrol.ErrUnavailable
				}
				if revoked.Load() {
					return visitorfixture.HTTPDecision{}, clientcontrol.ErrUnauthenticated
				}
				return sessionAllowed(time.Unix(0, deadline.Load()))
			}}
			policy, tokens := prepareSessionControl(t, control)
			access := &Browser{Subject: visitorscope.Scope{Kind: visitorscope.PublicURL, ID: visitorfixture.PublicURLID},
				Policy: policy, Tokens: tokens}
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if access.Handle(w, r) {
					return
				}
				_, guard, _, err := AuthorizeRequest(w, r, policy.Lease(), tokens)
				if err != nil {
					if access.RedirectRestricted(w, r, name != "share without browser login") {
						return
					}
					http.Error(w, "denied", http.StatusForbidden)
					return
				}
				defer guard.Finish()
				w.WriteHeader(http.StatusOK)
			})
			secret := visitorfixture.BrowserCookie
			cookie := BrowserCookieName + "=" + secret
			if share {
				cookie = ShareCookieName + "=shr_0123456789abcdefghijkl." + secret
			}
			_ = control.Credential(t, secret, share)
			tokens.mu.Lock()
			for _, source := range tokens.sources {
				source.used = time.Now().Add(-6 * time.Minute)
			}
			tokens.mu.Unlock()
			tokens.refresh(t.Context(), nil)
			serve := func(path, cookies string, navigate bool) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodGet, path, nil)
				r.Host = "route.example"
				r.TLS = &tls.ConnectionState{ServerName: "route.example"}
				r.Header.Set("Cookie", cookies)
				if navigate {
					r.Header.Set("Sec-Fetch-Mode", "navigate")
					r.Header.Set("Sec-Fetch-Dest", "document")
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w
			}
			if denied := serve("/settings", cookie, false); denied.Code != http.StatusForbidden {
				t.Fatal("session cookie bypassed missing visitor permission", denied.Code)
			}
			redirect := serve("/settings", cookie, true)
			if redirect.Code != http.StatusSeeOther || redirect.Header().Get("Location") != "/__tnl/team/renew?return=%2Fsettings" {
				t.Fatal("top-level visit did not offer session re-preparation", redirect.Code, redirect.Header().Get("Location"))
			}
			renewed := serve("/__tnl/team/renew?return=%2Fsettings", cookie, false)
			if renewed.Code != http.StatusSeeOther || renewed.Header().Get("Location") != "/settings" || len(renewed.Result().Cookies()) != 1 || renewed.Result().Cookies()[0].Name != VisitorTokenCookie {
				t.Fatal("valid session was not exchanged for a visitor cookie", renewed.Code, renewed.Body.String())
			}
			visitor := cookie + "; " + VisitorTokenCookie + "=" + renewed.Result().Cookies()[0].Value
			if allowed := serve("/settings", visitor, false); allowed.Code != http.StatusOK {
				t.Fatal("prepared visitor was denied", allowed.Code)
			}
			deadline.Store(time.Now().Add(2 * time.Minute).UnixNano())
			if repeated := serve("/__tnl/team/renew?return=%2Fsettings", cookie, false); repeated.Code != http.StatusSeeOther || len(repeated.Result().Cookies()) != 1 {
				t.Fatal("fresh session evidence could not advance a provisional token deadline", repeated.Code, repeated.Body.String())
			}
			deadline.Store(time.Now().Add(3 * time.Minute).UnixNano())
			tokens.refresh(t.Context(), nil)
			tokens.mu.Lock()
			var extended bool
			for _, source := range tokens.sources {
				extended = source.reprepared && source.parentDeadline.After(renewed.Result().Cookies()[0].Expires)
			}
			tokens.mu.Unlock()
			if !extended {
				t.Fatal("re-prepared session did not keep renewing beyond its first short token")
			}
			unavailable.Store(true)
			if unavailableResponse := serve("/__tnl/team/renew?return=%2Fsettings", cookie, false); unavailableResponse.Code != http.StatusServiceUnavailable || len(unavailableResponse.Result().Cookies()) != 0 {
				t.Fatal("issuer outage looked like session revocation", unavailableResponse.Code)
			}
			unavailable.Store(false)
			revoked.Store(true)
			if rejected := serve("/__tnl/team/renew?return=%2Fsettings", cookie, false); rejected.Code != http.StatusForbidden || len(rejected.Result().Cookies()) != 0 {
				t.Fatal("revoked parent renewed visitor permission", rejected.Code)
			}
		})
	}
}
