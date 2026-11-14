package httpaccess

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type challengeClient struct {
	supported bool
	redeem    func(context.Context, controlv1.RedeemHTTPChallengeRequest, string) (controlv1.HTTPChallengeClearance, error)
}

func (c challengeClient) Discovery(context.Context) (controlv1.ControlDiscovery, error) {
	return controlv1.ControlDiscovery{Turnstile: c.supported}, nil
}

func (c challengeClient) RedeemHTTPChallenge(ctx context.Context, body controlv1.RedeemHTTPChallengeRequest, token string) (controlv1.HTTPChallengeClearance, error) {
	return c.redeem(ctx, body, token)
}

func TestChallengePreparationAndNavigation(t *testing.T) {
	policy, update, _ := visitorfixture.Policy(t, true)
	client := challengeClient{supported: true, redeem: func(context.Context, controlv1.RedeemHTTPChallengeRequest, string) (controlv1.HTTPChallengeClearance, error) {
		t.Error("ordinary request contacted control")
		return controlv1.HTTPChallengeClearance{}, nil
	}}
	if _, err := PrepareChallenge(t.Context(), challengeClient{}, policy, update.View.Issuer, update.View.Scope, "run", 1, "token"); !errors.Is(err, ErrChallengeUnsupported) {
		t.Fatal("unconfigured server did not fail publication preparation", err)
	}
	c, err := PrepareChallenge(t.Context(), client, policy, update.View.Issuer, update.View.Scope, "run", 1, "token")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ method, mode, destination string }{
		{"GET", "", ""}, {"GET", "cors", "empty"}, {"GET", "navigate", "iframe"},
		{"POST", "navigate", "document"}, {"OPTIONS", "cors", "empty"}, {"HEAD", "navigate", "document"},
	} {
		r := visitorfixture.Request()
		r.Method = tc.method
		r.Header.Set("Sec-Fetch-Mode", tc.mode)
		r.Header.Set("Sec-Fetch-Dest", tc.destination)
		r.Header.Set("Accept", "text/html")
		r.Header.Set("User-Agent", "browser")
		r.Header.Set("Authorization", "Bearer arbitrary")
		w := httptest.NewRecorder()
		if c.Allow(w, r) || w.Code != 403 || w.Header().Get("Location") != "" || (tc.method != "HEAD" && !strings.Contains(w.Body.String(), `"challenge_required"`)) {
			t.Fatal("non-navigation request bypassed or started the challenge", tc, w.Code, w.Body.String())
		}
	}
	r := visitorfixture.Request()
	r.URL.Path, r.URL.RawQuery = "/sensitive/path", "secret=never-send-to-control"
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	w := httptest.NewRecorder()
	if c.Allow(w, r) || w.Code != 303 || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("top-level GET did not start the control flow", w.Code)
	}
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil || location.Scheme+"://"+location.Host != update.View.Issuer || strings.Contains(location.String(), "sensitive") || strings.Contains(location.String(), "secret") {
		t.Fatal("navigation leaked application path or query", location, err)
	}
	cookie := w.Result().Cookies()[0]
	raw, err := base64.RawURLEncoding.Strict().DecodeString(cookie.Value)
	digest := sha256.Sum256(raw)
	if err != nil || len(raw) != 32 || location.Query().Get("binding") != base64.RawURLEncoding.EncodeToString(digest[:]) ||
		cookie.Name != ChallengeBindingCookie || cookie.Domain != "" || cookie.Path != "/" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("publisher browser binding was not separate and host-only")
	}
}

func TestChallengeHandoffInstallsOnlyVerifiedFixedClearance(t *testing.T) {
	for _, scope := range []visitorscope.Scope{
		{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("A", 22)},
		{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("A", 22)},
	} {
		t.Run(string(scope.Kind), func(t *testing.T) {
			port := uint16(443)
			if scope.Kind == visitorscope.Service {
				port = 25443
			}
			policy, update, _ := visitorfixture.ScopePolicy(t, scope, "preview.example.test", port, true)
			now := time.Now().UTC().Truncate(time.Second)
			key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("h", 32)))
			expires := now.Add(visitortoken.ClearanceLifetime)
			token, err := visitortoken.SignClearance(update.View.Issuer, "http", key, visitortoken.Clearance{Scope: scope, Hostname: update.View.Hostname, Port: port, ExpiresAt: expires}, now)
			if err != nil {
				t.Fatal(err)
			}
			valid := controlv1.HTTPChallengeClearance{Clearance: token.Reveal(), ExpiresAt: expires}
			reply := valid
			calls := 0
			c, err := PrepareChallenge(t.Context(), challengeClient{supported: true, redeem: func(ctx context.Context, body controlv1.RedeemHTTPChallengeRequest, secret string) (controlv1.HTTPChallengeClearance, error) {
				calls++
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > 2*time.Second || body.Resource.Id != scope.ID || body.RunId != "run" || body.RunNumber != 7 || body.Handoff != "handoff" || secret != "run-token" || body.Binding != visitorfixture.BrowserCookie {
					t.Error("handoff lost exact run, binding, or request budget")
				}
				return reply, nil
			}}, policy, update.View.Issuer, scope, "run", 7, "run-token")
			if err != nil {
				t.Fatal(err)
			}
			request := func() *http.Request {
				r := visitorfixture.Request()
				r.URL.Path, r.URL.RawQuery = ChallengePath, "handoff=handoff"
				r.AddCookie(&http.Cookie{Name: ChallengeBindingCookie, Value: visitorfixture.BrowserCookie})
				return r
			}
			for _, response := range []controlv1.HTTPChallengeClearance{{Clearance: "bad", ExpiresAt: expires}, {Clearance: token.Reveal(), ExpiresAt: expires.Add(time.Second)}} {
				reply = response
				w := httptest.NewRecorder()
				c.Handle(w, request())
				if w.Code != 503 || len(w.Result().Cookies()) != 0 {
					t.Fatal("invalid control response installed clearance", w.Code)
				}
			}
			reply = valid
			w := httptest.NewRecorder()
			if !c.Handle(w, request()) || w.Code != 303 || w.Header().Get("Location") != "/" || len(w.Result().Cookies()) != 2 {
				t.Fatal("valid handoff did not install clearance", w.Code)
			}
			clearance := w.Result().Cookies()[0]
			if clearance.Name != ClearanceCookie || clearance.Value != token.Reveal() || !clearance.Expires.Equal(expires) ||
				clearance.Domain != "" || !clearance.Secure || !clearance.HttpOnly || clearance.SameSite != http.SameSiteLaxMode {
				t.Fatal("clearance lost its host-only cookie boundary or absolute expiry")
			}
			before := calls
			r := visitorfixture.Request()
			r.AddCookie(clearance)
			if !c.Allow(httptest.NewRecorder(), r) || calls != before {
				t.Fatal("valid clearance was not verified locally")
			}
			r.Header.Add("Cookie", ClearanceCookie+"=malformed")
			if c.Allow(httptest.NewRecorder(), r) {
				t.Fatal("duplicate clearance bypassed the challenge")
			}
			clean := StripCookies(request())
			if clean.Header.Get("Cookie") != "" {
				t.Fatal("binding cookie reached application boundary")
			}
			clean = StripCookies(r)
			if clean.Header.Get("Cookie") != "" {
				t.Fatal("clearance cookie reached application boundary")
			}
		})
	}
}

func TestChallengeHandoffsRejectWithoutQueuing(t *testing.T) {
	policy, update, _ := visitorfixture.Policy(t, true)
	entered, release := make(chan struct{}, 4), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	c, err := PrepareChallenge(t.Context(), challengeClient{supported: true, redeem: func(ctx context.Context, _ controlv1.RedeemHTTPChallengeRequest, _ string) (controlv1.HTTPChallengeClearance, error) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return controlv1.HTTPChallengeClearance{}, errors.New("unavailable")
	}}, policy, update.View.Issuer, update.View.Scope, "run", 1, "secret")
	if err != nil {
		t.Fatal(err)
	}
	request := func() *httptest.ResponseRecorder {
		r := visitorfixture.Request()
		r.URL.Path, r.URL.RawQuery = ChallengePath, "handoff=handoff"
		r.AddCookie(&http.Cookie{Name: ChallengeBindingCookie, Value: visitorfixture.BrowserCookie})
		w := httptest.NewRecorder()
		c.Handle(w, r)
		return w
	}
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() { request() })
		<-entered
	}
	w := request()
	if w.Code != 503 || w.Header().Get("Retry-After") != "1" {
		t.Error("full handoff gate queued another control request", w.Code)
	}
	unblock()
	workers.Wait()
}
