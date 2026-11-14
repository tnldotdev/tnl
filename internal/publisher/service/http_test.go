package service

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	protectionpolicy "github.com/tnldotdev/tnl/internal/policy/httpprotection"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/httpprotection"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func serviceHTTPFixture(t *testing.T, target http.Handler) (*http.Client, *visitorlease.Lease, visitorlease.Update, visitortoken.Token) {
	t.Helper()
	return serviceHTTPFixtureWithInspector(t, target, nil)
}

func serviceHTTPFixtureWithInspector(t *testing.T, target http.Handler, inspection *httpprotection.Inspector, configure ...func(*HTTP)) (*http.Client, *visitorlease.Lease, visitorlease.Update, visitortoken.Token) {
	t.Helper()
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("A", 22)}
	policy, update, token := visitorfixture.ScopePolicy(t, scope, "preview.example.test", 25443, false)
	upstream := httptest.NewServer(target)
	t.Cleanup(upstream.Close)
	certificate := visitorfixture.Certificate(t, update.View.Hostname)
	header := tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream,
		ServiceID: scope.ID, ServiceRunID: "srun_" + strings.Repeat("R", 22), RunNumber: 1, SourceIP: "192.0.2.1",
		VisitorConnectionID: "vc_" + strings.Repeat("V", 22), PublisherConnectionID: "pc_" + strings.Repeat("P", 22), ConnectionAssignmentRevision: 1, ExpiresAt: time.Now().Add(time.Minute),
		PublicService: &tunnelv1.PublicServiceAdmission{IngressID: "ingress", IngressRunID: "ir_" + strings.Repeat("I", 22), IngressLeaseRevision: 1, DestinationPort: 25443}},
		RelayID: "relay", RelayServiceID: "relay-service", RelayRunID: "rr_" + strings.Repeat("R", 22), RelayLeaseRevision: 1, LeaseExpiresAt: time.Now().Add(time.Minute)}
	if err := header.Validate(); err != nil {
		t.Fatal(err)
	}
	frontend := HTTP{Subject: scope, RunID: header.ServiceRunID, Number: 1, Hostname: update.View.Hostname, Port: update.View.Port, Header: header, Policy: policy}
	if inspection == nil {
		var err error
		inspection, err = httpprotection.New(protectionpolicy.Settings{})
		if err != nil {
			t.Fatal(err)
		}
	}
	frontend.protection = inspection
	for _, apply := range configure {
		apply(&frontend)
	}
	t.Cleanup(func() {
		if err := inspection.Close(); err != nil {
			t.Error(err)
		}
	})
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: visitorfixture.Roots(t, certificate)}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		visitor, raw := net.Pipe()
		server := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13})
		done := make(chan error, 1)
		go func() {
			defer server.Close()
			done <- frontend.Forward(t.Context(), server, servicestream.HTTPTarget{Address: strings.TrimPrefix(upstream.URL, "http://"), Transport: targettransport.Transport{Protocol: config.ProtocolHTTP}})
		}()
		t.Cleanup(func() {
			_ = visitor.Close()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("service HTTP visitor did not stop")
			}
		})
		return visitor, nil
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}, policy, update, token
}

type serviceChallengeControl struct{ HTTPControl }

func (serviceChallengeControl) Discovery(context.Context) (controlv1.ControlDiscovery, error) {
	return controlv1.ControlDiscovery{Turnstile: true}, nil
}

func enableServiceChallenge(t *testing.T, f *HTTP) {
	t.Helper()
	var err error
	f.Protection.Challenge = protectionpolicy.Turnstile
	f.challenge, err = httpaccess.PrepareChallenge(t.Context(), serviceChallengeControl{}, f.Policy, "https://control.example.test", f.Subject, f.RunID, f.Number, "run-token")
	if err != nil {
		t.Fatal(err)
	}
}

func TestChallengeSavedHTTPFrontendKeepsAuthorizationSeparate(t *testing.T) {
	var forwarded atomic.Int32
	client, _, update, token := serviceHTTPFixtureWithInspector(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		if httpaccess.SuppliedCookieCount(r, httpaccess.ClearanceCookie) != 0 {
			t.Error("clearance reached target")
		}
		w.WriteHeader(204)
	}), nil, func(f *HTTP) {
		enableServiceChallenge(t, f)
	})
	now := time.Now().UTC().Truncate(time.Second)
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("h", 32)))
	clearance, err := visitortoken.SignClearance(update.View.Issuer, "http", key,
		visitortoken.Clearance{Scope: update.View.Scope, Hostname: update.View.Hostname, Port: update.View.Port, ExpiresAt: now.Add(30 * time.Minute)}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		access, clearance bool
		status            int
	}{{true, false, 403}, {false, true, 403}, {true, true, 204}} {
		r, _ := http.NewRequestWithContext(t.Context(), "GET", "https://preview.example.test:25443/", nil)
		if tc.access {
			r.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
		}
		if tc.clearance {
			r.AddCookie(&http.Cookie{Name: httpaccess.ClearanceCookie, Value: clearance.Reveal()})
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != tc.status {
			t.Fatal("service challenge bypassed authorization or failed to require clearance", response.StatusCode, tc)
		}
	}
	if forwarded.Load() != 1 {
		t.Fatal("uncleared or unauthorized request reached target")
	}
}

func TestChallengeTemporaryBlockPrecedesBrowserPreparation(t *testing.T) {
	inspection, err := httpprotection.Prepare(t.Context(), protectionpolicy.Settings{TemporaryBlocks: true},
		func(context.Context, protectionpolicy.Rejections) error {
			t.Error("a challenge counted toward an attack block")
			return nil
		},
		func(netip.Addr, time.Time) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	client, _, _, token := serviceHTTPFixtureWithInspector(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("blocked challenge request reached target")
	}), inspection, func(f *HTTP) { enableServiceChallenge(t, f) })
	for _, path := range []string{"/", httpaccess.ChallengePath + "?handoff=unused"} {
		r, _ := http.NewRequestWithContext(t.Context(), "GET", "https://preview.example.test:25443"+path, nil)
		r.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		r.Header.Set("Sec-Fetch-Dest", "document")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != 403 || response.Header.Get("Location") != "" || len(response.Cookies()) != 0 {
			t.Fatal("source block was converted to a challenge flow", response.StatusCode)
		}
	}
}

func TestTemporaryBlocksSavedHTTPFrontend(t *testing.T) {
	reports := make(chan protectionpolicy.Rejections, 1)
	inspection, err := httpprotection.Prepare(t.Context(), protectionpolicy.Settings{TemporaryBlocks: true}, func(_ context.Context, r protectionpolicy.Rejections) error { reports <- r; return nil }, func(netip.Addr, time.Time) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	client, _, _, token := serviceHTTPFixtureWithInspector(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("blocked service request reached target") }), inspection)
	for n := range protectionpolicy.BlockThreshold + 1 {
		path := "https://preview.example.test:25443/"
		if n < protectionpolicy.BlockThreshold {
			path += "?q=" + url.QueryEscape("<script>alert(1)</script>")
		}
		r, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		r.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
		r.Header.Set("X-Forwarded-For", "203.0.113.1")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != 403 {
			t.Fatal("saved service frontend missed rejection or local source block", response.StatusCode)
		}
	}
	select {
	case report := <-reports:
		if report.SourceIP != "192.0.2.1" || report.Validate(time.Now()) != nil {
			t.Fatal("saved service reported untrusted source metadata", report)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("saved service rejections did not reach reporting worker")
	}
}

func TestServiceHTTPDefaultProtection(t *testing.T) {
	var forwarded atomic.Int32
	client, _, _, token := serviceHTTPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		w.WriteHeader(204)
	}))
	r, _ := http.NewRequestWithContext(t.Context(), "GET", "https://preview.example.test:25443/?q="+url.QueryEscape("<script>alert(1)</script>"), nil)
	r.Header.Set(httpaccess.VisitorTokenHeader, token.Reveal())
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 403 || response.Header.Get("Tnl-Error-Code") != "TNL_HTTP_PROTECTION_REJECTED" || forwarded.Load() != 0 {
		t.Fatal("managed service request was not rejected before target access", response.Status, forwarded.Load())
	}
}

type serviceHTTPGrantControl struct {
	HTTPControl
	client httpaccess.TokenClient
}

func (c serviceHTTPGrantControl) IssueVisitorToken(ctx context.Context, request controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
	return c.client.IssueVisitorToken(ctx, request)
}

func TestServiceHTTPShareRedemptionKeepsRenewingBeyondFirstPermission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))
		scope := visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("A", 22)}
		policy, err := httpaccess.PreparePolicy(t.Context(), &visitorfixture.PolicyClient{Key: key}, scope, "run", 1, "run-secret", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer policy.Close()
		grantID := "shg_" + strings.Repeat("G", 22)
		refresh := "vrf1." + grantID + "." + strings.Repeat("A", 43)
		issuer := &visitorfixture.TokenClient{Issue: func(_ context.Context, request controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
			var source controlv1.VisitorTokenGrantSource
			if request.Resource.Id != scope.ID || request.Resource.Kind != "service" || json.Unmarshal(request.Source, &source) != nil || source.Kind != "grant" || source.Credential != refresh {
				t.Fatal("share redemption or renewal lost its exact resource/source")
			}
			view, _, _ := policy.Lease().Current()
			facts := visitortoken.Permission{Scope: scope, Hostname: view.Hostname, Port: view.Port, VisitorPolicyRevision: view.VisitorPolicyRevision, Subject: visitortoken.Grant{GrantID: grantID, Kind: "share"}, ExpiresAt: time.Now().Add(5 * time.Minute)}
			token, err := visitortoken.Sign(view.Issuer, "test-key", key, facts, time.Now())
			return controlv1.VisitorTokenResponse{Resource: request.Resource, Hostname: view.Hostname, Port: int(view.Port), VisitorToken: token.Reveal(), VisitorPolicyRevision: view.VisitorPolicyRevision, ExpiresAt: facts.ExpiresAt}, err
		}}
		tokens, err := httpaccess.StartTokens(t.Context(), issuer, policy.Lease(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tokens.Close()
		frontend := HTTP{Subject: scope, Control: serviceHTTPGrantControl{client: issuer}, browser: &httpaccess.Browser{Subject: scope, Policy: policy, Tokens: tokens}}
		response := httptest.NewRecorder()
		frontend.share(response, httptest.NewRequest(http.MethodGet, "/__tnl/share/"+refresh, nil))
		if response.Code != http.StatusSeeOther {
			t.Fatal("share redemption failed", response.Code, response.Body.String())
		}
		initial := response.Result().Cookies()[0]
		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatal(err)
		}
		renew := httptest.NewRequest(http.MethodGet, "https://service.example/__tnl/team/renew?return=/", nil)
		jar.SetCookies(renew.URL, response.Result().Cookies())
		time.Sleep(4*time.Minute + 2*time.Second)
		synctest.Wait()
		visit := visitorfixture.Request()
		view, _, _ := policy.Lease().Current()
		visit.Host = net.JoinHostPort(view.Hostname, "443")
		visit.Header.Set(httpaccess.VisitorTokenHeader, initial.Value)
		prepared := httptest.NewRecorder()
		_, guard, _, err := httpaccess.AuthorizeRequest(prepared, visit, policy.Lease(), tokens)
		if err != nil {
			t.Fatal("renewed service share could not authorize its visitor", err)
		}
		guard.Finish()
		cookies := prepared.Result().Cookies()
		if len(cookies) != 1 || cookies[0].Name != httpaccess.VisitorTokenCookie || !cookies[0].Expires.After(initial.Expires) || issuer.Calls.Load() != 2 {
			t.Fatal("share renewal was capped at its first short permission", cookies, issuer.Calls.Load())
		}
		// an idle browser has not received the background renewal's cookie.
		// after its first permission expires, the share must still recover it.
		time.Sleep(time.Minute)
		for _, cookie := range jar.Cookies(renew.URL) {
			renew.AddCookie(cookie)
		}
		if _, err := renew.Cookie(httpaccess.VisitorTokenCookie); err == nil {
			t.Fatal("fixture retained the expired visitor permission")
		}
		renewed := httptest.NewRecorder()
		if !frontend.browser.Handle(renewed, renew) || renewed.Code != http.StatusSeeOther {
			t.Fatal("idle service share could not renew after its first permission expired", renewed.Code, renewed.Body.String())
		}
		jar.SetCookies(renew.URL, renewed.Result().Cookies())
		var restored bool
		for _, cookie := range jar.Cookies(renew.URL) {
			restored = restored || cookie.Name == httpaccess.VisitorTokenCookie
		}
		if !restored || issuer.Calls.Load() != 3 {
			t.Fatal("idle renewal did not restore a permission through the original share", restored, issuer.Calls.Load())
		}
	})
}

func TestServiceHTTPCredentialPrecedenceFailsClosed(t *testing.T) {
	var forwarded atomic.Int64
	client, _, _, token := serviceHTTPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		if r.Header.Get(httpaccess.VisitorTokenHeader) != "" || r.Header.Get("Cookie") != "app=value" || r.Header.Get("Authorization") != "application-secret" || r.Header.Get("X-Forwarded-For") != "" {
			t.Error("visitor credentials or untrusted source reached the target")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, tc := range []struct {
		name    string
		headers http.Header
		status  int
	}{
		{"absent", nil, 403},
		{"permission", http.Header{httpaccess.VisitorTokenHeader: {token.Reveal()}}, 204},
		{"malformed", http.Header{httpaccess.VisitorTokenHeader: {"invalid"}}, 403},
		{"duplicate", http.Header{httpaccess.VisitorTokenHeader: {token.Reveal(), token.Reveal()}}, 403},
		{"ambiguous", http.Header{httpaccess.VisitorTokenHeader: {token.Reveal()}, "Cookie": {httpaccess.VisitorTokenCookie + "=" + token.Reveal()}}, 403},
		{"retired", http.Header{"Tnl-Access-Token": {"invalid"}, httpaccess.VisitorTokenHeader: {token.Reveal()}}, 403},
		{"refresh", http.Header{httpaccess.VisitorTokenHeader: {"vrf1.shg_" + strings.Repeat("A", 22) + "." + strings.Repeat("A", 43)}}, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := http.NewRequestWithContext(t.Context(), "GET", "https://preview.example.test:25443/", nil)
			if tc.headers != nil {
				r.Header = tc.headers.Clone()
			}
			r.AddCookie(&http.Cookie{Name: "app", Value: "value"})
			r.Header.Set("Authorization", "application-secret")
			r.Header.Set("X-Forwarded-For", "203.0.113.9")
			response, err := client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			_, _ = io.Copy(io.Discard, response.Body)
			if response.StatusCode != tc.status {
				t.Fatalf("status %d, want %d", response.StatusCode, tc.status)
			}
		})
	}
	if forwarded.Load() != 1 {
		t.Fatalf("forwarded %d requests", forwarded.Load())
	}
}
