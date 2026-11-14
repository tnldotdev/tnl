package public

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/control/turnstile"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type challengeStore struct {
	httpChallengeStore
	attempt             controlstate.HTTPChallengeAttempt
	browser             []byte
	claims, completions int
}

func (s *challengeStore) BeginHTTPChallenge(_ context.Context, scope visitorscope.Scope, browser, publisher []byte, now time.Time) (controlstate.HTTPChallengeAttempt, error) {
	s.browser = browser
	s.attempt = controlstate.HTTPChallengeAttempt{ID: "cha_" + strings.Repeat("A", 22), Scope: scope, Hostname: "preview.example.test", Port: 25443, ExpiresAt: now.Add(5 * time.Minute)}
	return s.attempt, nil
}

func (s *challengeStore) ReadHTTPChallenge(_ context.Context, id string, hash []byte, _ time.Time) (controlstate.HTTPChallengeAttempt, error) {
	if id != s.attempt.ID || string(hash) != string(s.browser) {
		return controlstate.HTTPChallengeAttempt{}, controlstate.ErrHTTPChallenge
	}
	return s.attempt, nil
}

func (s *challengeStore) ClaimHTTPChallenge(ctx context.Context, id string, hash []byte, now time.Time) error {
	if _, err := s.ReadHTTPChallenge(ctx, id, hash, now); err != nil {
		return err
	}
	s.claims++
	return nil
}

func (s *challengeStore) CompleteHTTPChallenge(_ context.Context, proof turnstile.VerifiedAttempt, _ time.Time) (controlstate.HTTPChallengeHandoff, error) {
	if proof.ID() != s.attempt.ID {
		return controlstate.HTTPChallengeHandoff{}, controlstate.ErrHTTPChallenge
	}
	s.completions++
	return controlstate.HTTPChallengeHandoff{Origin: "https://preview.example.test:25443", Secret: "single-use-secret"}, nil
}

type challengeRoundTripper func(*http.Request) (*http.Response, error)

func (f challengeRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestChallengeControlBrowserBindingOriginAndProviderFailure(t *testing.T) {
	store := &challengeStore{}
	outage := false
	providerCalls := 0
	h, err := NewHandler(Config{ControlURL: "https://control.example.test", TurnstileSiteKey: "site", TurnstileSecretKey: "secret",
		HTTPClient: &http.Client{Transport: challengeRoundTripper(func(r *http.Request) (*http.Response, error) {
			providerCalls++
			if store.claims != providerCalls {
				t.Error("provider work started before claiming the attempt")
			}
			status := 200
			if outage {
				status = 503
			}
			body, _ := json.Marshal(map[string]any{"success": true, "hostname": "control.example.test", "action": turnstile.Action, "cdata": store.attempt.ID, "challenge_ts": time.Now()})
			return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body)))}, nil
		})}}, Stores{HTTPChallenges: store}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	serve := func(r *http.Request) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	start := "/v1/browser/challenge/start?resource_kind=service&resource_id=svc_" + strings.Repeat("A", 22) + "&binding=" + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	w := serve(httptest.NewRequest("GET", start, nil))
	if w.Code != 303 || len(w.Result().Cookies()) != 1 {
		t.Fatal("challenge start did not bind browser", w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	decoded, _ := base64.RawURLEncoding.DecodeString(cookie.Value)
	hash := sha256.Sum256(decoded)
	if string(hash[:]) != string(store.browser) || cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("control stored raw browser binding or lost cookie flags")
	}
	path := w.Header().Get("Location")
	if got := serve(httptest.NewRequest("GET", path, nil)); got.Code != 403 {
		t.Fatal("challenge page ignored browser binding", got.Code)
	}
	page := httptest.NewRequest("GET", path, nil)
	page.AddCookie(cookie)
	w = serve(page)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") || strings.Contains(w.Body.String(), "single-use-secret") {
		t.Fatal("challenge page lost isolation", w.Code)
	}
	post := func(origin string, bound bool) *http.Request {
		r := httptest.NewRequest("POST", path, strings.NewReader(url.Values{"response": {"widget-token"}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", origin)
		if bound {
			r.AddCookie(cookie)
		}
		return r
	}
	for _, r := range []*http.Request{post("https://attacker.example", true), post("https://control.example.test", false)} {
		if got := serve(r); got.Code != 403 || providerCalls != 0 {
			t.Fatal("unbound or cross-origin form reached Siteverify", got.Code)
		}
	}
	w = serve(post("https://control.example.test", true))
	if w.Code != 303 || w.Header().Get("Location") != "https://preview.example.test:25443/__tnl/challenge?handoff=single-use-secret" || store.completions != 1 {
		t.Fatal("verified attempt lost its exact approved origin", w.Code, w.Body.String())
	}
	outage = true
	w = serve(post("https://control.example.test", true))
	if w.Code != 503 || w.Header().Get("Retry-After") != "1" || store.completions != 1 {
		t.Fatal("provider outage completed or bypassed the challenge", w.Code)
	}
}

func TestChallengeControlSharesProtectionPreparationGate(t *testing.T) {
	h, err := NewHandler(Config{ControlURL: "https://control.example.test", TurnstileSiteKey: "site", TurnstileSecretKey: "secret"}, Stores{HTTPChallenges: &challengeStore{}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for range cap(httpProtectionReports) {
		httpProtectionReports <- struct{}{}
	}
	defer func() {
		for range cap(httpProtectionReports) {
			<-httpProtectionReports
		}
	}()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/v1/browser/challenge/start?resource_kind=service&resource_id=x&binding=x", nil))
	if w.Code != 503 || w.Header().Get("Retry-After") != "1" {
		t.Fatal("full report gate admitted challenge preparation", w.Code)
	}
}

func TestChallengeConfiguredCapability(t *testing.T) {
	for _, keys := range [][2]string{{"", ""}, {"public-site", "private-secret"}, {"public-site", ""}, {"", "private-secret"}} {
		h, err := NewHandler(Config{ControlURL: "https://control.example.test", TurnstileSiteKey: keys[0], TurnstileSecretKey: keys[1]}, Stores{}, nil, nil)
		if (keys[0] == "") != (keys[1] == "") {
			if !errors.Is(err, turnstile.ErrConfiguration) {
				t.Fatal("partial challenge configuration did not fail startup", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/v1/discovery", nil))
		var result controlv1.ControlDiscovery
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Turnstile != (keys[0] != "") {
			t.Fatal("discovery did not advertise configured challenge support", w.Code)
		}
		if strings.Contains(w.Body.String(), "private-secret") {
			t.Fatal("discovery exposed the verification secret")
		}
	}
}

func TestChallengeUnconfiguredServerRejectsPublicationBeforeRunCreation(t *testing.T) {
	store := &publicURLMutationStoreStub{publicURL: controlstate.PublicURL{ID: "url", TeamID: "team"}}
	store.publisher = &controlstate.PublisherIdentity{ID: "publisher", GrantID: "grant", KeyID: "key", CreatorID: "identity",
		Scope: controlstate.PublisherScope{TeamID: "team", Kind: "saved_public_url", PublicURLID: "url"}}
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"http_protection":{"challenge":"turnstile"}}`))
	r.Header.Set("Authorization", "Bearer publisher-access")
	r.Header.Set("Idempotency-Key", "retry")
	w := httptest.NewRecorder()
	(&handler{store: store, dependencies: Stores{PublisherRuns: store}}).CreatePublishRun(w, r, "url", controlv1.CreatePublishRunParams{})
	if w.Code != 503 || !strings.Contains(w.Body.String(), "Turnstile is not configured") || store.sessionRequest.PublicURLID != "" {
		t.Fatal("unconfigured server prepared a challenged publication", w.Code, w.Body.String())
	}
}
