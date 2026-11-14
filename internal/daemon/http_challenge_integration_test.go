package daemon

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/turnstile"
	daemonconfig "github.com/tnldotdev/tnl/internal/daemon/config"
	protectionpolicy "github.com/tnldotdev/tnl/internal/policy/httpprotection"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
)

type challengeTransport func(*http.Request) (*http.Response, error)

func (f challengeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestIntegrationHTTPChallengeBrowserFlow(t *testing.T) {
	var providerCalls atomic.Int32
	var attempt atomic.Value
	var outage atomic.Bool
	provider := &http.Client{Transport: challengeTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://challenges.cloudflare.com/turnstile/v0/siteverify" {
			return http.DefaultTransport.RoundTrip(r)
		}
		providerCalls.Add(1)
		if err := r.ParseForm(); err != nil || r.PostForm.Get("secret") != "fixture-secret" || r.PostForm.Get("response") != "widget-response" {
			t.Error("Siteverify did not receive its exact credential and response")
		}
		status := 200
		if outage.Load() {
			status = 503
		}
		body, _ := json.Marshal(map[string]any{"success": true, "hostname": "control.integration.test", "action": turnstile.Action, "cdata": attempt.Load(), "challenge_ts": time.Now()})
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body)))}, nil
	})}
	f := newStandalonePublishFixtureOptions(t, "challenge", func(c *daemonconfig.Config) {
		c.TurnstileSiteKey, c.TurnstileSecretKey = "fixture-site", "fixture-secret"
	}, provider)
	var forwarded atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		for _, name := range []string{httpaccess.ClearanceCookie, httpaccess.ChallengeBindingCookie} {
			if httpaccess.SuppliedCookieCount(r, name) != 0 {
				t.Error("challenge credential reached the application")
			}
		}
		w.WriteHeader(204)
	}))
	cleanupIntegrationHTTPServer(t, target, f.owner)
	quic, tcp := f.connectors()
	config := f.identity.publisherConfig(target.URL, quic, tcp)
	config.Protection.Challenge = "turnstile"
	handle := startOwnedIntegrationPublisher(t, f.owner, config, f.diagnostics)
	ready := f.waitReady(t, handle)
	jar, _ := cookiejar.New(nil)
	app := *f.visitor.client
	app.Jar, app.CheckRedirect = jar, func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	control := *f.controlHTTP
	control.Jar, control.CheckRedirect = jar, app.CheckRedirect
	do := func(client *http.Client, method, address string, body io.Reader, headers map[string]string) *http.Response {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), method, address, body)
		if err != nil {
			t.Fatal(err)
		}
		for name, value := range headers {
			r.Header.Set(name, value)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = response.Body.Close() })
		return response
	}
	checkStatus := func(response *http.Response, status int) {
		t.Helper()
		if response.StatusCode != status {
			body, _ := io.ReadAll(response.Body)
			t.Fatalf("HTTP status %d want %d: %s", response.StatusCode, status, body)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
	}
	response := do(&app, "POST", ready.PublicURL+"/form", strings.NewReader("private-body"), map[string]string{"Accept": "text/html"})
	checkStatus(response, 403)
	nav := map[string]string{"Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
	response = do(&app, "GET", ready.PublicURL+"/private?secret=private-query", nil, nav)
	checkStatus(response, 303)
	start := response.Header.Get("Location")
	if strings.Contains(start, "private") {
		t.Fatal("application body or return query leaked to control")
	}
	response = do(&control, "GET", start, nil, nil)
	checkStatus(response, 303)
	page := "https://control.integration.test" + response.Header.Get("Location")
	attempt.Store(page[strings.LastIndex(page, "/")+1:])
	response = do(&control, "GET", page, nil, nil)
	pageBody, _ := io.ReadAll(response.Body)
	checkStatus(response, 200)
	if !strings.Contains(string(pageBody), "fixture-site") || strings.Contains(string(pageBody), "fixture-secret") {
		t.Fatal("control page lost the public widget key or disclosed its secret")
	}
	form := url.Values{"response": {"widget-response"}}.Encode()
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://control.integration.test"}
	response = do(&control, "POST", page, strings.NewReader(form), headers)
	checkStatus(response, 303)
	handoff := response.Header.Get("Location")
	response = do(&app, "GET", handoff, nil, nil)
	checkStatus(response, 303)
	checkStatus(do(&app, "GET", ready.PublicURL, nil, nil), 204)
	// handoffs are single use; replaying one cannot issue another cookie.
	checkStatus(do(&app, "GET", handoff, nil, nil), 403)
	// valid clearance still passes through WAF inspection, including during
	// provider outages. ordinary requests never call control or Siteverify.
	outage.Store(true)
	before := providerCalls.Load()
	checkStatus(do(&app, "GET", ready.PublicURL+"/?q="+url.QueryEscape("<script>alert(1)</script>"), nil, nil), 403)
	checkStatus(do(&app, "POST", ready.PublicURL+"/form", strings.NewReader("benign"), map[string]string{"Content-Type": "text/plain"}), 204)
	if providerCalls.Load() != before || forwarded.Load() != 2 {
		t.Fatal("ordinary requests contacted Siteverify or bypassed WAF")
	}
	// a second browser cannot obtain new clearance during an outage. claiming
	// its attempt still happens before Siteverify, so retry requires a new one.
	otherJar, _ := cookiejar.New(nil)
	otherApp, otherControl := app, control
	otherApp.Jar, otherControl.Jar = otherJar, otherJar
	response = do(&otherApp, "GET", ready.PublicURL, nil, nav)
	checkStatus(response, 303)
	response = do(&otherControl, "GET", response.Header.Get("Location"), nil, nil)
	checkStatus(response, 303)
	otherPage := "https://control.integration.test" + response.Header.Get("Location")
	attempt.Store(otherPage[strings.LastIndex(otherPage, "/")+1:])
	checkStatus(do(&otherControl, "POST", otherPage, strings.NewReader(form), headers), 503)
	checkStatus(do(&otherControl, "POST", otherPage, strings.NewReader(form), headers), 403)
	checkStatus(do(&otherApp, "GET", ready.PublicURL, nil, nil), 403)
	before = providerCalls.Load()
	stopIntegrationPublisher(t, handle)
	config.Protection.Exclusions = []protectionpolicy.Exclusion{{RuleID: 942100, Path: "/search", Parameter: "q"}}
	replacement := startOwnedIntegrationPublisher(t, f.owner, config, f.diagnostics)
	restarted := f.waitReady(t, replacement)
	if restarted.PublicURLID != ready.PublicURLID {
		t.Fatal("restart did not preserve the protected resource")
	}
	checkStatus(do(&app, "GET", restarted.PublicURL, nil, nil), 204)
	if providerCalls.Load() != before {
		t.Fatal("same-resource app restart or WAF edit forced a new challenge")
	}
	stopIntegrationPublisher(t, replacement)
}
