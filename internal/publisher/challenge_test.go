package publisher

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	protectionpolicy "github.com/tnldotdev/tnl/internal/policy/httpprotection"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type publicURLChallengeControl struct{ t *testing.T }

func (publicURLChallengeControl) Discovery(context.Context) (controlv1.ControlDiscovery, error) {
	return controlv1.ControlDiscovery{Turnstile: true}, nil
}

func (c publicURLChallengeControl) RedeemHTTPChallenge(context.Context, controlv1.RedeemHTTPChallengeRequest, string) (controlv1.HTTPChallengeClearance, error) {
	c.t.Error("ordinary application or share preparation contacted challenge redemption")
	return controlv1.HTTPChallengeClearance{}, errors.New("unexpected challenge handoff")
}

func TestChallengePublicURLSharePreparationAndRevocation(t *testing.T) {
	client := &shareAccessTestClient{
		shareID: "shr_0123456789abcdefghijkl", cookie: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("c", 32))), active: true,
	}
	authority := preparedShareAuthority(t, client)
	policy := authority.policy.Lease()
	view, _, _ := policy.Current()
	challenge, err := httpaccess.PrepareChallenge(t.Context(), publicURLChallengeControl{t}, policy, view.Issuer, view.Scope, "pr_test", 1, "run-token")
	if err != nil {
		t.Fatal(err)
	}
	forwarded := 0
	route, err := NewPublicURLServer(PublicURLServerConfig{
		Hostname: "route.example", PublicURLID: view.Scope.ID, PublishRunID: "pr_test", PublishRunNumber: 1,
		VisitorPolicy: policy, VisitorTokens: authority.tokens,
		ShareAccess: &httpaccess.Shares{Client: client, RunID: "pr_test", Number: 1},
		Protection:  protectionpolicy.Settings{WAF: protectionpolicy.Off, Challenge: protectionpolicy.Turnstile}, ChallengeAccess: challenge,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			forwarded++
			if r.Header.Get("Cookie") != "app_session=ok" {
				t.Error("publisher cookies reached the application")
			}
			w.WriteHeader(http.StatusNoContent)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	serve := func(path string, cookies []*http.Cookie, navigation bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Host, r.TLS = "route.example", &tls.ConnectionState{ServerName: "route.example"}
		r = r.WithContext(context.WithValue(r.Context(), denialContextKey{}, true))
		r.AddCookie(&http.Cookie{Name: "app_session", Value: "ok"})
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		if navigation {
			r.Header.Set("Sec-Fetch-Mode", "navigate")
			r.Header.Set("Sec-Fetch-Dest", "document")
		}
		w := httptest.NewRecorder()
		serveTestPublicRequest(t, route, w, r)
		return w
	}
	if w := serve("/", nil, true); w.Code != 403 || w.Header().Get("Location") != "" {
		t.Fatal("challenge started before visitor authorization", w.Code)
	}
	link := "/__tnl/share/" + client.shareID + "." + base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
	w := serve(link, nil, false)
	if w.Code != 303 || w.Header().Get("Location") != "https://route.example/" || len(w.Result().Cookies()) != 2 {
		t.Fatal("challenge intercepted share preparation", w.Code)
	}
	shareCookies := w.Result().Cookies()
	if w := serve("/", shareCookies, false); w.Code != 403 || !strings.Contains(w.Body.String(), `"challenge_required"`) {
		t.Fatal("a share bypassed the explicit challenge", w.Code)
	}
	if w := serve("/", shareCookies, true); w.Code != 303 || !strings.HasPrefix(w.Header().Get("Location"), view.Issuer+"/v1/browser/challenge/start?") {
		t.Fatal("authorized navigation did not start the challenge", w.Code)
	}
	now := time.Now().UTC().Truncate(time.Second)
	clearance, err := visitortoken.SignClearance(view.Issuer, "live", ed25519.NewKeyFromSeed([]byte(strings.Repeat("l", 32))),
		visitortoken.Clearance{Scope: view.Scope, Hostname: view.Hostname, Port: view.Port, ExpiresAt: now.Add(visitortoken.ClearanceLifetime)}, now)
	if err != nil {
		t.Fatal(err)
	}
	clearanceCookie := &http.Cookie{Name: httpaccess.ClearanceCookie, Value: clearance.Reveal()}
	if w := serve("/", []*http.Cookie{clearanceCookie}, false); w.Code != 403 {
		t.Fatal("clearance granted visitor authorization", w.Code)
	}
	shareCookies = append(shareCookies, clearanceCookie)
	if w := serve("/", shareCookies, false); w.Code != 204 || forwarded != 1 {
		t.Fatal("authorized and cleared visitor did not reach the application", w.Code)
	}
	authority.Mu.Lock()
	client.active = false
	authority.Mu.Unlock()
	if err := authority.policy.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	if w := serve("/", shareCookies, false); w.Code != 403 || forwarded != 1 {
		t.Fatal("valid clearance bypassed share revocation", w.Code)
	}
}
