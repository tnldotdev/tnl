package service

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func serviceHTTPFixture(t *testing.T, target http.Handler) (*http.Client, *visitorlease.Lease, visitorlease.Update, visitortoken.Token) {
	return serviceHTTPProtocolFixture(t, target, false)
}

func serviceHTTPProtocolFixture(t *testing.T, target http.Handler, h2 bool) (*http.Client, *visitorlease.Lease, visitorlease.Update, visitortoken.Token) {
	return serviceHTTPApplicationFixture(t, target, h2, false)
}

func serviceHTTPApplicationFixture(t *testing.T, target http.Handler, h2, inline bool, audits ...serviceaudit.Sink) (*http.Client, *visitorlease.Lease, visitorlease.Update, visitortoken.Token) {
	t.Helper()
	return serviceHTTPConfiguredFixture(t, target, h2, inline, func(frontend *HTTP) {
		if len(audits) != 0 {
			frontend.AuditSink = audits[0]
		}
	})
}

func serviceHTTPConfiguredFixture(t *testing.T, target http.Handler, h2, inline bool, configure func(*HTTP), configureTarget ...func(*servicestream.HTTPTarget)) (*http.Client, *visitorlease.Lease, visitorlease.Update, visitortoken.Token) {
	t.Helper()
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("A", 22)}
	policy, update, token := visitorfixture.ScopePolicy(t, scope, "preview.example.test", 443, false)
	application := servicestream.HTTPTarget{Handler: target}
	if !inline {
		upstream := httptest.NewServer(target)
		t.Cleanup(upstream.Close)
		application = servicestream.HTTPTarget{Address: strings.TrimPrefix(upstream.URL, "http://"), Transport: targettransport.Transport{Protocol: config.ProtocolHTTP}}
	}
	for _, configure := range configureTarget {
		configure(&application)
	}
	certificate := visitorfixture.Certificate(t, update.View.Hostname)
	header := tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream,
		ServiceID: scope.ID, ServiceRunID: "srun_" + strings.Repeat("R", 22), RunNumber: 1, SourceIP: "192.0.2.1",
		VisitorConnectionID: "vc_" + strings.Repeat("V", 22), PublisherConnectionID: "pc_" + strings.Repeat("P", 22), ConnectionAssignmentRevision: 1, ExpiresAt: time.Now().Add(time.Minute),
		PublicService: &tunnelv1.PublicServiceAdmission{IngressID: "ingress", IngressRunID: "ir_" + strings.Repeat("I", 22), IngressLeaseRevision: 1, DestinationPort: 443}},
		RelayID: "relay", RelayServiceID: "relay-service", RelayRunID: "rr_" + strings.Repeat("R", 22), RelayLeaseRevision: 1, LeaseExpiresAt: time.Now().Add(time.Minute)}
	if err := header.Validate(); err != nil {
		t.Fatal(err)
	}
	frontend := HTTP{Control: serviceHTTPControl{}, Subject: scope, RunID: header.ServiceRunID, Number: 1, Token: credentials.ServiceRunToken("run-token"), Hostname: update.View.Hostname, Port: update.View.Port, Header: header, Source: netip.MustParseAddrPort("192.0.2.1:1234"), Policy: policy, ReserveCapacity: func(context.Context) error { return nil }}
	frontend.preparations = make(chan struct{}, 16)
	if configure != nil {
		configure(&frontend)
	}
	transport := &http.Transport{ForceAttemptHTTP2: h2, TLSClientConfig: &tls.Config{RootCAs: visitorfixture.Roots(t, certificate)}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		visitor, raw := net.Pipe()
		server := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2", "http/1.1"}})
		done := make(chan error, 1)
		go func() {
			defer server.Close()
			done <- frontend.Forward(t.Context(), server, application)
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

type serviceHTTPShareControl struct {
	serviceHTTPControl
	redeem func(context.Context, string, string, controlv1.RedeemServiceShareRequest, credentials.ServiceRunToken) (controlv1.ShareRedemption, error)
}

type serviceHTTPControl struct {
	HTTPControl
}

func (c serviceHTTPShareControl) RedeemServiceShare(ctx context.Context, service, run string, request controlv1.RedeemServiceShareRequest, token credentials.ServiceRunToken) (controlv1.ShareRedemption, error) {
	return c.redeem(ctx, service, run, request, token)
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
		shareID := "shr_" + strings.Repeat("G", 22)
		secret := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
		cookie := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("c", 32)))
		runID := "srun_" + strings.Repeat("R", 22)
		runToken := credentials.ServiceRunToken("service-run-secret")
		issuer := &visitorfixture.TokenClient{Issue: func(_ context.Context, request controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
			var source controlv1.VisitorTokenShareSessionSource
			if request.Resource.Id != scope.ID || request.Resource.Kind != "service" || json.Unmarshal(request.Source, &source) != nil || source.Kind != "share_session" || source.ShareId != shareID || source.Secret != cookie {
				t.Fatal("share redemption or renewal lost its exact resource/source")
			}
			view, _, _ := policy.Lease().Current()
			facts := visitortoken.Permission{Scope: scope, Hostname: view.Hostname, Port: view.Port, VisitorPolicyRevision: view.VisitorPolicyRevision, Subject: visitortoken.Share{ShareID: shareID}, ExpiresAt: time.Now().Add(5 * time.Minute)}
			token, err := visitortoken.Sign(view.Issuer, "test-key", key, facts, time.Now())
			return controlv1.VisitorTokenResponse{Resource: request.Resource, Hostname: view.Hostname, Port: int(view.Port), VisitorToken: token.Reveal(), VisitorPolicyRevision: view.VisitorPolicyRevision, ExpiresAt: facts.ExpiresAt}, err
		}}
		tokens, err := httpaccess.StartTokens(t.Context(), issuer, policy.Lease(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tokens.Close()
		control := serviceHTTPShareControl{redeem: func(ctx context.Context, service, run string, request controlv1.RedeemServiceShareRequest, token credentials.ServiceRunToken) (controlv1.ShareRedemption, error) {
			if service != scope.ID || run != runID || token != runToken || request.RunNumber != 1 || request.ShareId == nil ||
				*request.ShareId != shareID || request.Secret == nil || *request.Secret != secret || request.HandoffToken != nil {
				t.Fatal("share redemption lost its service run or original link")
			}
			source, err := json.Marshal(controlv1.VisitorTokenShareSessionSource{Kind: controlv1.VisitorTokenShareSession, ShareId: shareID, Secret: cookie})
			if err != nil {
				t.Fatal(err)
			}
			permission, err := issuer.IssueVisitorToken(ctx, controlv1.VisitorTokenRequest{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: scope.ID}, Source: source})
			return controlv1.ShareRedemption{ShareId: shareID, CookieSecret: cookie, ExpiresAt: time.Now().Add(time.Hour), NextUrl: "https://service.example/", Permission: permission}, err
		}}
		frontend := HTTP{Subject: scope, RunID: runID, Number: 1, Token: runToken, Control: control,
			browser: &httpaccess.Browser{Subject: scope, Client: control, RunID: runID, Number: 1, Token: runToken, Policy: policy, Tokens: tokens}}
		response := httptest.NewRecorder()
		frontend.share(response, httptest.NewRequest(http.MethodGet, "/__tnl/share/"+shareID+"."+secret, nil))
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
		if r.Header.Get(httpaccess.VisitorTokenHeader) != "" || r.Header.Get("Cookie") != "app=value" || r.Header.Get("Authorization") != "application-secret" ||
			r.Header.Get("X-Forwarded-For") != "192.0.2.1" || r.Header.Get("Forwarded") != "" || r.Header.Get("X-Real-IP") != "" {
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
			r, _ := http.NewRequestWithContext(t.Context(), "GET", "https://preview.example.test/", nil)
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

func TestServiceHTTPAnonymousAccessKeepsPolicyAndCredentialFences(t *testing.T) {
	var forwarded atomic.Int64
	client, policy, update, _ := serviceHTTPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		if r.Header.Get(httpaccess.VisitorTokenHeader) != "" {
			t.Error("visitor credential reached the target")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	client.Transport.(*http.Transport).MaxConnsPerHost = 1
	apply := func(anonymous, enabled bool, ip *ippolicy.Policy) {
		t.Helper()
		now := time.Now()
		update.View.VisitorPolicyRevision++
		update.View.ObservedAt, update.View.ValidUntil = now, now.Add(10*time.Second)
		update.Anonymous, update.Enabled, update.IP = anonymous, enabled, ip
		if err := policy.Apply(policy.Begin(), update); err != nil {
			t.Fatal(err)
		}
	}
	request := func(headers http.Header, status int) {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test/", nil)
		if err != nil {
			t.Fatal(err)
		}
		if headers != nil {
			r.Header = headers.Clone()
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		if response.StatusCode != status {
			t.Fatalf("status %d, want %d", response.StatusCode, status)
		}
	}
	apply(true, true, nil)
	request(nil, http.StatusNoContent)
	for _, headers := range []http.Header{
		{httpaccess.VisitorTokenHeader: {"invalid"}},
		{httpaccess.VisitorTokenHeader: {"invalid", "invalid"}},
		{"Tnl-Access-Token": {"invalid"}},
		{"Cookie": {httpaccess.VisitorTokenCookie + "=invalid"}},
		{"Cookie": {httpaccess.BrowserCookieName + "=invalid"}},
		{"Cookie": {httpaccess.ShareCookieName + "=invalid"}},
	} {
		request(headers, http.StatusForbidden)
	}
	key := [32]byte{1}
	entry, err := ippolicy.Hash(key, netip.MustParsePrefix("203.0.113.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	ip, err := ippolicy.New(key, []ippolicy.Entry{entry})
	if err != nil {
		t.Fatal(err)
	}
	apply(true, true, &ip)
	// HTTP headers cannot replace the original source supplied by the relay.
	request(http.Header{"X-Forwarded-For": {"203.0.113.1"}}, http.StatusServiceUnavailable)
	apply(true, true, nil)
	request(nil, http.StatusNoContent)
	apply(false, true, nil)
	request(nil, http.StatusForbidden)
	apply(true, true, nil)
	request(nil, http.StatusNoContent)
	// a 204 header can reach the client before its handler releases the policy
	// guard. a reserved request on the same sole connection proves that release
	// before disablement; it reaches neither the target nor an application budget.
	barrier, err := client.Get("https://preview.example.test/__tnl/unused-policy-barrier")
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, barrier.Body)
	closeErr := barrier.Body.Close()
	if barrier.StatusCode != http.StatusNotFound || readErr != nil || closeErr != nil {
		t.Fatal("HTTP policy guard barrier failed", barrier.StatusCode, readErr, closeErr)
	}
	apply(true, false, nil)
	request(nil, http.StatusServiceUnavailable)
	if forwarded.Load() != 3 {
		t.Fatalf("forwarded %d requests, want 3", forwarded.Load())
	}
}

func TestServiceHTTPIdentityCookieDoesNotReplaceVisitorPolicy(t *testing.T) {
	var forwarded atomic.Int32
	client, policy, update, _ := serviceHTTPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		if r.Header.Get("Cookie") != "" {
			t.Error("identity-only browser cookie reached the application")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	apply := func(anonymous bool) {
		t.Helper()
		update.Anonymous = anonymous
		update.View.VisitorPolicyRevision++
		update.View.ObservedAt = time.Now()
		update.View.ValidUntil = update.View.ObservedAt.Add(10 * time.Second)
		if err := policy.Apply(policy.Begin(), update); err != nil {
			t.Fatal(err)
		}
	}
	visit := func(cookie string, want int) {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test/", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Cookie", cookie)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if _, err := io.Copy(io.Discard, response.Body); err != nil || response.StatusCode != want {
			t.Fatal("identity cookie changed visitor policy", response.StatusCode, err)
		}
	}
	cookie := httpaccess.BrowserCookieName + "=" + visitorfixture.BrowserCookie
	apply(true)
	visit(cookie, http.StatusNoContent)
	visit(cookie+"; "+cookie, http.StatusForbidden)
	visit(httpaccess.BrowserCookieName+"=invalid", http.StatusForbidden)
	apply(false)
	visit(cookie, http.StatusForbidden)
	if forwarded.Load() != 1 {
		t.Fatal("browser identity granted restricted access", forwarded.Load())
	}
}

func TestServiceHTTPRestrictingAccessCancelsAnonymousRequest(t *testing.T) {
	started, stopped := make(chan struct{}), make(chan struct{})
	client, policy, update, _ := serviceHTTPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(stopped)
	}))
	apply := func(anonymous bool) {
		t.Helper()
		now := time.Now()
		update.View.VisitorPolicyRevision++
		update.View.ObservedAt, update.View.ValidUntil = now, now.Add(10*time.Second)
		update.Anonymous = anonymous
		if err := policy.Apply(policy.Begin(), update); err != nil {
			t.Fatal(err)
		}
	}
	apply(true)
	done := make(chan struct{})
	go func() {
		defer close(done)
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test/", nil)
		if err != nil {
			t.Error(err)
			return
		}
		response, err := client.Do(request)
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			response.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("anonymous request did not reach its target")
	}
	apply(false)
	for _, event := range []<-chan struct{}{stopped, done} {
		select {
		case <-event:
		case <-time.After(5 * time.Second):
			t.Fatal("restricting HTTP access did not stop and join the anonymous request")
		}
	}
}
