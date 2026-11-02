package publisher

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
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func serviceHTTPFixture(t *testing.T, target http.Handler) (*http.Client, *visitorlease.Lease, visitorlease.Update, visitortoken.Token) {
	t.Helper()
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("A", 22)}
	policy, update, token := httpPermissionScopeFixture(t, scope, "preview.example.test", 25443, false)
	upstream := httptest.NewServer(target)
	t.Cleanup(upstream.Close)
	certificate := publicURLTestCertificate(t, update.View.Hostname)
	header := tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream,
		ServiceID: scope.ID, ServiceRunID: "srun_" + strings.Repeat("R", 22), RunNumber: 1, SourceIP: "192.0.2.1",
		VisitorConnectionID: "vc_" + strings.Repeat("V", 22), PublisherConnectionID: "pc_" + strings.Repeat("P", 22), ConnectionAssignmentRevision: 1, ExpiresAt: time.Now().Add(time.Minute),
		PublicService: &tunnelv1.PublicServiceAdmission{IngressID: "ingress", IngressRunID: "ir_" + strings.Repeat("I", 22), IngressLeaseRevision: 1, DestinationPort: 25443}},
		RelayID: "relay", RelayServiceID: "relay-service", RelayRunID: "rr_" + strings.Repeat("R", 22), RelayLeaseRevision: 1, LeaseExpiresAt: time.Now().Add(time.Minute)}
	if err := header.Validate(); err != nil {
		t.Fatal(err)
	}
	frontend := ServiceHTTP{Subject: scope, RunID: header.ServiceRunID, Number: 1, Hostname: update.View.Hostname, Port: update.View.Port, Header: header, Policy: policy}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: rootsForCertificate(t, certificate)}, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		visitor, raw := net.Pipe()
		server := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13})
		done := make(chan error, 1)
		go func() {
			defer server.Close()
			done <- frontend.Forward(t.Context(), server, ServiceHTTPTarget{Address: strings.TrimPrefix(upstream.URL, "http://"), Transport: targettransport.Transport{Protocol: config.ProtocolHTTP}})
		}()
		t.Cleanup(func() { _ = visitor.Close(); awaitPublisherTest(t, done) })
		return visitor, nil
	}}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}, policy, update, token
}

type serviceHTTPGrantControl struct {
	ServiceHTTPControl
	client browserTokenClient
}

func (c serviceHTTPGrantControl) IssueVisitorToken(ctx context.Context, request controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
	return c.client.IssueVisitorToken(ctx, request)
}

func TestServiceHTTPShareRedemptionKeepsRenewingBeyondFirstPermission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))
		scope := visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("A", 22)}
		policy, err := prepareVisitorPolicy(t.Context(), &policyClientFixture{key: key}, scope, "run", 1, "run-secret", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer policy.Close()
		grantID := "shg_" + strings.Repeat("G", 22)
		refresh := "vrf1." + grantID + "." + strings.Repeat("A", 43)
		issuer := &browserTokenClientFixture{issue: func(_ context.Context, request controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
			var source controlv1.VisitorTokenGrantSource
			if request.Resource.Id != scope.ID || request.Resource.Kind != "service" || json.Unmarshal(request.Source, &source) != nil || source.Kind != "grant" || source.Credential != refresh {
				t.Fatal("share redemption or renewal lost its exact resource/source")
			}
			view, _, _ := policy.lease.Current()
			facts := visitortoken.Permission{Scope: scope, Hostname: view.Hostname, Port: view.Port, VisitorPolicyRevision: view.VisitorPolicyRevision, Subject: visitortoken.Grant{GrantID: grantID, Kind: "share"}, ExpiresAt: time.Now().Add(5 * time.Minute)}
			token, err := visitortoken.Sign(view.Issuer, "test-key", key, facts, time.Now())
			return controlv1.VisitorTokenResponse{Resource: request.Resource, Hostname: view.Hostname, Port: int(view.Port), VisitorToken: token.Reveal(), VisitorPolicyRevision: view.VisitorPolicyRevision, ExpiresAt: facts.ExpiresAt}, err
		}}
		tokens, err := startBrowserTokens(t.Context(), issuer, policy.lease, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tokens.Close()
		frontend := ServiceHTTP{Subject: scope, Control: serviceHTTPGrantControl{client: issuer}, browser: &browserAccess{subject: scope, policy: policy, tokens: tokens}}
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
		current, done, found := tokens.use(visitortoken.Token(initial.Value), nil)
		done()
		if !found || !current.ExpiresAt.After(initial.Expires) || issuer.calls.Load() != 2 {
			t.Fatal("share renewal was capped at its first short permission", found, issuer.calls.Load())
		}
		// an idle browser has not received the background renewal's cookie.
		// after its first permission expires, the share must still recover it.
		time.Sleep(time.Minute)
		for _, cookie := range jar.Cookies(renew.URL) {
			renew.AddCookie(cookie)
		}
		if _, err := renew.Cookie(visitorTokenCookie); err == nil {
			t.Fatal("fixture retained the expired visitor permission")
		}
		renewed := httptest.NewRecorder()
		if !frontend.browser.handle(renewed, renew) || renewed.Code != http.StatusSeeOther {
			t.Fatal("idle service share could not renew after its first permission expired", renewed.Code, renewed.Body.String())
		}
		jar.SetCookies(renew.URL, renewed.Result().Cookies())
		var restored bool
		for _, cookie := range jar.Cookies(renew.URL) {
			restored = restored || cookie.Name == visitorTokenCookie
		}
		if !restored || issuer.calls.Load() != 3 {
			t.Fatal("idle renewal did not restore a permission through the original share", restored, issuer.calls.Load())
		}
	})
}

func TestServiceHTTPCredentialPrecedenceFailsClosed(t *testing.T) {
	var forwarded atomic.Int64
	client, _, _, token := serviceHTTPFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		if r.Header.Get(visitorTokenHeader) != "" || r.Header.Get("Cookie") != "app=value" || r.Header.Get("Authorization") != "application-secret" || r.Header.Get("X-Forwarded-For") != "" {
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
		{"permission", http.Header{visitorTokenHeader: {token.Reveal()}}, 204},
		{"malformed", http.Header{visitorTokenHeader: {"invalid"}}, 403},
		{"duplicate", http.Header{visitorTokenHeader: {token.Reveal(), token.Reveal()}}, 403},
		{"ambiguous", http.Header{visitorTokenHeader: {token.Reveal()}, "Cookie": {visitorTokenCookie + "=" + token.Reveal()}}, 403},
		{"retired", http.Header{"Tnl-Access-Token": {"invalid"}, visitorTokenHeader: {token.Reveal()}}, 403},
		{"refresh", http.Header{visitorTokenHeader: {"vrf1.shg_" + strings.Repeat("A", 22) + "." + strings.Repeat("A", 43)}}, 403},
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
