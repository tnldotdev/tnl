package service

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type serviceBrowserControl struct {
	HTTPControl
	origin string
	policy httpaccess.PolicyClient
	tokens httpaccess.TokenClient
	ip     *controlv1.VisitorPolicyIP
}

func (c serviceBrowserControl) ControlURL() string { return c.origin }

func (c serviceBrowserControl) ReadPublisherVisitorPolicy(ctx context.Context, request controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	update, err := c.policy.ReadPublisherVisitorPolicy(ctx, request, token)
	update.Policy.Ip = c.ip
	return update, err
}

func (c serviceBrowserControl) IssueVisitorToken(ctx context.Context, request controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
	return c.tokens.IssueVisitorToken(ctx, request)
}

func TestServiceBrowserControlOrigins(t *testing.T) {
	for _, test := range []struct {
		origin string
		want   string
	}{
		{"https://control.example.test", "https://control.example.test"},
		{"https://CONTROL.example.test:443/", "https://control.example.test"},
		{"http://localhost:8445", "http://localhost:8445"},
		{"http://LOCALHOST:8445/", "http://localhost:8445"},
		{"http://127.0.0.1:8445", "http://127.0.0.1:8445"},
		{"http://[::1]:8445", "http://[::1]:8445"},
		{"http://control.example.test", ""},
		{"http://192.168.1.1:8445", ""},
		{"http://0.0.0.0:8445", ""},
		{"http://localhost.example.test:8445", ""},
		{"http://127.0.0.1.example.test:8445", ""},
		{"http://user@localhost:8445", ""},
		{"http://localhost:8445/path", ""},
		{"http://localhost:8445?query", ""},
		{"http://localhost:8445#fragment", ""},
		{"http://localhost:65536", ""},
		{"https://user@control.example.test", ""},
		{"https://control.example.test/path", ""},
		{"", ""},
	} {
		t.Run(test.origin, func(t *testing.T) {
			key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))
			policy := &visitorfixture.PolicyClient{Key: key}
			control := &serviceBrowserControl{HTTPControl: &clientcontrol.Client{}, origin: test.origin, policy: policy,
				tokens: &visitorfixture.TokenClient{Issue: func(context.Context, controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
					t.Error("browser login tried to issue visitor permission")
					return controlv1.VisitorTokenResponse{}, visitortoken.ErrToken
				}}}
			facts := HTTP{Control: control, Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_0123456789abcdefghijkl"},
				RunID: "srun_0123456789abcdefghijkl", Number: 7, Token: credentials.ServiceRunToken("run-secret")}
			prepared, closeHTTP, err := PrepareHTTP(t.Context(), facts)
			if test.want == "" {
				if !errors.Is(err, servicestream.ErrEndpoint) || closeHTTP != nil || prepared.browser != nil || policy.Calls.Load() != 0 {
					t.Fatal("invalid control origin enabled browser access or started policy work", err)
				}
				return
			}
			if err != nil {
				t.Fatal("valid control origin disabled browser access", err)
			}
			defer closeHTTP()
			access := prepared.browser
			if access == nil || access.ControlURL != test.want || access.Client != control || access.Subject != facts.Subject ||
				access.RunID != facts.RunID || access.Number != facts.Number || access.Token != facts.Token ||
				access.Policy == nil || access.Policy.Lease() != prepared.Policy || access.Tokens == nil {
				t.Fatal("browser access lost its control origin or service run binding")
			}
			navigation := httptest.NewRequest(http.MethodGet, "https://preview.example.test/settings?tab=profile", nil)
			navigation.Header.Set("Sec-Fetch-Mode", "navigate")
			navigation.Header.Set("Sec-Fetch-Dest", "document")
			redirect := httptest.NewRecorder()
			if !access.RedirectRestricted(redirect, navigation, true) || redirect.Code != http.StatusSeeOther {
				t.Fatal("restricted browser navigation did not start sign-in")
			}
			login := httptest.NewRequest(http.MethodGet, redirect.Header().Get("Location"), nil)
			response := httptest.NewRecorder()
			if !access.Handle(response, login) || response.Code != http.StatusSeeOther {
				t.Fatal("browser sign-in did not redirect to control", response.Code, response.Body.String())
			}
			location, err := url.Parse(response.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			query := location.Query()
			location.RawQuery = ""
			if location.String() != test.want+"/v1/browser/service-login" || query.Get("service_id") != facts.Subject.ID ||
				query.Get("return_path") != "/settings?tab=profile" || query.Has("public_url_id") {
				t.Fatalf("browser sign-in redirect = %q", response.Header().Get("Location"))
			}
			cookies := response.Result().Cookies()
			if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Domain != "" {
				t.Fatal("browser sign-in weakened the visitor cookie")
			}
		})
	}
}

func TestServiceBrowserAccessRequiresHTTPOwnerAndClient(t *testing.T) {
	facts := HTTP{Subject: visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_0123456789abcdefghijkl"},
		RunID: "srun_0123456789abcdefghijkl", Number: 7, Token: credentials.ServiceRunToken("run-secret")}
	if prepared, closeHTTP, err := PrepareHTTP(t.Context(), facts); !errors.Is(err, servicestream.ErrEndpoint) || closeHTTP != nil || prepared.browser != nil {
		t.Fatal("browser access enabled without a browser-capable HTTP control client", err)
	}
	config, control := lifecycleFixture(t)
	approved, err := control.GetPublisherService(t.Context(), config.ServiceID, "")
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := newManagedPrepared(control.prep, approved, config)
	if err != nil {
		t.Fatal(err)
	}
	_, closeRun, err := configureServiceRun(t.Context(), config, prepared, control.setup, control, config.State, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := closeRun(); err != nil {
			t.Error("close configured run", err)
		}
	}()
	header := tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{PublicService: &tunnelv1.PublicServiceAdmission{DestinationPort: 25443}}}
	if _, certificateOnly := prepared.managedVisitor(header, func(context.Context) error { return nil }).(servicestream.CertificateVisitor); !certificateOnly {
		t.Fatal("TCP service enabled the HTTP browser frontend")
	}
}

func TestServiceBrowserTeamAccessIsAdditiveAndStripsCredentials(t *testing.T) {
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))
	policy := &visitorfixture.PolicyClient{Key: key}
	var member, invited atomic.Bool
	member.Store(true)
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: "svc_" + strings.Repeat("A", 22)}
	issuer := &visitorfixture.TokenClient{Issue: func(_ context.Context, request controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
		var source controlv1.VisitorTokenBrowserSessionSource
		if request.Resource.Kind != "service" || request.Resource.Id != scope.ID || json.Unmarshal(request.Source, &source) != nil ||
			source.Kind != controlv1.VisitorTokenBrowserSession || source.Secret != visitorfixture.BrowserCookie && source.Secret != "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA" {
			t.Fatal("browser permission lost its exact service or session source")
		}
		if !member.Load() && !invited.Load() {
			return controlv1.VisitorTokenResponse{}, &clientcontrol.ProblemError{Status: http.StatusForbidden}
		}
		facts := visitortoken.Permission{Scope: scope, Hostname: "preview.example.test", Port: 443,
			VisitorPolicyRevision: max(int64(1), policy.Revision.Load()),
			Subject:               visitortoken.Browser{IdentityID: "ident_" + strings.Repeat("B", 22), SessionID: "cs_" + strings.Repeat("C", 22)},
			ExpiresAt:             time.Now().Add(5 * time.Minute).Truncate(time.Second)}
		token, err := visitortoken.Sign("https://control.example.test", "test-key", key, facts, time.Now())
		return controlv1.VisitorTokenResponse{Resource: request.Resource, Hostname: facts.Hostname, Port: int(facts.Port),
			VisitorPolicyRevision: facts.VisitorPolicyRevision, ExpiresAt: facts.ExpiresAt, VisitorToken: token.Reveal()}, err
	}}
	ipKey := [32]byte{1}
	allowedSource, err := ippolicy.Hash(ipKey, netip.MustParsePrefix("192.0.2.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	control := &serviceBrowserControl{HTTPControl: serviceHTTPControl{}, origin: "https://control.example.test", policy: policy, tokens: issuer,
		ip: &controlv1.VisitorPolicyIP{Key: ipKey[:], Prefixes: []controlv1.HashedIPPrefix{{
			Family: controlv1.HashedIPPrefixFamily(allowedSource.Family), PrefixLength: allowedSource.Bits, Digest: allowedSource.Digest,
		}}}}
	cookies := make(chan string, 4)
	var frontend HTTP
	client, _, _, _ := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		cookies <- request.Header.Get("Cookie")
		w.WriteHeader(http.StatusOK)
	}), false, false, func(f *HTTP) {
		f.Control, f.Token = control, credentials.ServiceRunToken("run-secret")
		var err error
		var closeHTTP func()
		frontend, closeHTTP, err = PrepareHTTP(t.Context(), *f)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(closeHTTP)
		*f = frontend
	})
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	serve := func(path, cookie string, navigate bool) *http.Response {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if cookie != "" {
			request.Header.Set("Cookie", cookie)
		}
		if navigate {
			request.Header.Set("Accept", "text/html")
			request.Header.Set("Sec-Fetch-Mode", "navigate")
			request.Header.Set("Sec-Fetch-Dest", "document")
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	credential := func(secret string) string {
		t.Helper()
		source := visitorfixture.BrowserSource(secret)
		permission, err := issuer.IssueVisitorToken(t.Context(), controlv1.VisitorTokenRequest{
			Resource: controlv1.VisitorResourceScope{Kind: "service", Id: scope.ID}, Source: source,
		})
		if err != nil {
			t.Fatal(err)
		}
		permission, err = frontend.browser.PrepareSessionToken(t.Context(), source, permission)
		if err != nil {
			t.Fatal(err)
		}
		return "app_session=ok; " + httpaccess.BrowserCookieName + "=" + secret + "; " +
			httpaccess.ShareCookieName + "=shr_0123456789abcdefghijkl." + visitorfixture.BrowserCookie + "; " +
			httpaccess.LoginAttemptCookieName + "=1; " + httpaccess.VisitorTokenCookie + "=" + permission.VisitorToken
	}
	refresh := func() {
		t.Helper()
		policy.Revision.Add(1)
		if err := frontend.browser.Policy.Refresh(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	policy.Revision.Store(1)
	if response := serve("/settings", "", false); response.StatusCode != http.StatusForbidden {
		t.Fatal("visitor without permission reached the local service", response.StatusCode)
	}
	redirect := serve("/settings?tab=profile", "", true)
	if redirect.StatusCode != http.StatusSeeOther || redirect.Header.Get("Location") != "/__tnl/team/login?return=%2Fsettings%3Ftab%3Dprofile" {
		t.Fatal("restricted navigation did not start browser sign-in", redirect.StatusCode, redirect.Header.Get("Location"))
	}
	login := serve("/__tnl/team/login?return=%2Fsettings", "", false)
	if login.StatusCode != http.StatusSeeOther || !strings.HasPrefix(login.Header.Get("Location"), "https://control.example.test/v1/browser/service-login?") {
		t.Fatal("browser login did not reach control", login.StatusCode, login.Header.Get("Location"))
	}
	visitorCookie := credential(visitorfixture.BrowserCookie)
	if response := serve("/settings", visitorCookie, false); response.StatusCode != http.StatusOK {
		t.Fatal("signed-in team member was denied", response.StatusCode)
	}
	if got := <-cookies; got != "app_session=ok" {
		t.Fatalf("local service received browser credentials: %q", got)
	}
	member.Store(false)
	refresh()
	if response := serve("/settings", visitorCookie, false); response.StatusCode != http.StatusForbidden {
		t.Fatal("revoked team membership retained visitor access", response.StatusCode)
	}
	invited.Store(true)
	refresh()
	visitorCookie = credential("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA")
	if response := serve("/settings", visitorCookie, false); response.StatusCode != http.StatusOK {
		t.Fatal("invited identity outside the team was denied", response.StatusCode)
	}
	if got := <-cookies; got != "app_session=ok" {
		t.Fatalf("local service received invited visitor credentials: %q", got)
	}
	invited.Store(false)
	refresh()
	if response := serve("/settings", visitorCookie, false); response.StatusCode != http.StatusForbidden {
		t.Fatal("allowed source IP bypassed revoked visitor access", response.StatusCode)
	}
	if response := serve("/settings", "", false); response.StatusCode != http.StatusForbidden {
		t.Fatal("allowed source IP replaced visitor permission", response.StatusCode)
	}
	if response := serve("/__tnl/team/login", "", false); response.StatusCode != http.StatusSeeOther {
		t.Fatal("optional sign-in required a preview team grant or rejected an allowed source IP", response.StatusCode)
	}
	if len(cookies) != 0 {
		t.Fatal("denied requests reached the local service", len(cookies))
	}
}
