package service

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// this authority changes a share's permission revision, not the frontend's
// lease directly. explicit Refresh must install the revocation.
type shareRevocationPolicy struct {
	visitorfixture.PolicyClient
	service, run string
	number       int64
	revoked      atomic.Bool
	ip           *controlv1.VisitorPolicyIP
}

func (c *shareRevocationPolicy) ReadPublisherVisitorPolicy(ctx context.Context, request controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	if request.Resource.Kind != "service" || request.Resource.Id != c.service ||
		request.RunId != c.run || request.RunNumber != c.number || token != "run-secret" {
		return controlv1.VisitorPolicyUpdate{}, visitortoken.ErrBinding
	}
	if c.revoked.Load() {
		c.Revision.Store(2)
	}
	update, err := c.PolicyClient.ReadPublisherVisitorPolicy(ctx, request, token)
	update.Policy.Ip = c.ip
	return update, err
}

func TestServiceHTTPShareRevocationAfterTwoApplicationRequests(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		for _, priorIP := range []bool{false, true} {
			name := map[bool]string{false: "http1", true: "http2"}[h2] + "/" +
				map[bool]string{false: "without-ip-filter", true: "with-ip-admission"}[priorIP]
			t.Run(name, func(t *testing.T) {
				shareRevocationSequence(t, h2, priorIP, false)
			})
		}
	}
}

func TestServiceHTTPShareBearerWithExpiredCookieUsesCurrentDecision(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1", true: "http2"}[h2], func(t *testing.T) {
			shareRevocationSequence(t, h2, false, true)
		})
	}
}

func shareRevocationSequence(t *testing.T, h2, priorIP, expiredCookie bool) {
	t.Helper()
	shareID := "shr_" + strings.Repeat("S", 22)
	secret := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
	cookie := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("c", 32)))
	var policy *httpaccess.Policy
	var authority *shareRevocationPolicy
	var permission controlv1.VisitorTokenResponse
	var redemptions, forwarded, capacity atomic.Int32
	client, _, _, _ := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		if r.Header.Get("Cookie") != "app_session=ok" || r.Header.Get(httpaccess.VisitorTokenHeader) != "" ||
			r.Header.Get(httpaccess.ShareHeaderName) != "" || r.Header.Get("Tnl-Access-Token") != "" ||
			r.Header.Get("Authorization") != "Bearer unchanged-application" ||
			r.Header.Get("Forwarded") != "" || r.Header.Get("X-Real-IP") != "" ||
			r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("X-Forwarded-Host") != "" {
			t.Error("share permission changed application authentication or leaked visitor credentials/source headers")
		}
		w.WriteHeader(http.StatusNoContent)
	}), h2, true, func(f *HTTP) {
		f.Token = "run-secret"
		authority = &shareRevocationPolicy{service: f.Subject.ID, run: f.RunID, number: f.Number}
		authority.Key = ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))
		if priorIP {
			key := [32]byte{1}
			entry, err := ippolicy.Hash(key, netip.MustParsePrefix("192.0.2.0/24"))
			if err != nil {
				t.Fatal(err)
			}
			authority.ip = &controlv1.VisitorPolicyIP{Key: key[:], Prefixes: []controlv1.HashedIPPrefix{
				{Family: controlv1.HashedIPPrefixFamily(entry.Family), PrefixLength: entry.Bits, Digest: entry.Digest},
			}}
		}
		var err error
		policy, err = httpaccess.PreparePolicy(t.Context(), authority, f.Subject, f.RunID, f.Number, f.Token.String(), nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(policy.Close)
		tokens, err := httpaccess.StartTokens(t.Context(), &visitorfixture.TokenClient{Issue: func(context.Context, controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
			t.Error("ordinary share request fetched another permission")
			return controlv1.VisitorTokenResponse{}, visitortoken.ErrToken
		}}, policy.Lease(), nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(tokens.Close)
		scope, run, number, runToken := f.Subject, f.RunID, f.Number, f.Token
		control := serviceHTTPShareControl{redeem: func(_ context.Context, service, gotRun string, request controlv1.RedeemServiceShareRequest, token credentials.ServiceRunToken) (controlv1.ShareRedemption, error) {
			if authority.revoked.Load() || service != scope.ID || gotRun != run || token != runToken || request.RunNumber != number ||
				request.ShareId == nil || *request.ShareId != shareID || request.Secret == nil || *request.Secret != secret || request.HandoffToken != nil {
				return controlv1.ShareRedemption{}, visitortoken.ErrBinding
			}
			redemptions.Add(1)
			view, _, _ := policy.Lease().Current()
			now := time.Now()
			facts := visitortoken.Permission{Scope: scope, Hostname: view.Hostname, Port: view.Port,
				VisitorPolicyRevision: view.VisitorPolicyRevision, Subject: visitortoken.Share{ShareID: shareID},
				ExpiresAt: now.Add(5 * time.Minute).Truncate(time.Second)}
			signed, err := visitortoken.Sign(view.Issuer, "test-key", authority.Key, facts, now)
			permission = controlv1.VisitorTokenResponse{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: service},
				Hostname: facts.Hostname, Port: int(facts.Port), VisitorPolicyRevision: facts.VisitorPolicyRevision,
				ExpiresAt: facts.ExpiresAt, VisitorToken: signed.Reveal()}
			return controlv1.ShareRedemption{ShareId: shareID, CookieSecret: cookie, ExpiresAt: now.Add(time.Hour),
				NextUrl: "https://preview.example.test/", Permission: permission}, err
		}}
		f.Control, f.Policy = control, policy.Lease()
		f.browser = &httpaccess.Browser{Subject: scope, Client: control, RunID: run, Number: number, Token: runToken, Policy: policy, Tokens: tokens}
		f.ReserveCapacity = func(context.Context) error { capacity.Add(1); return nil }
	})
	transport := client.Transport.(*http.Transport)
	transport.MaxConnsPerHost = 1
	var dials atomic.Int32
	dial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		return dial(ctx, network, address)
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	visit := func(path string, headers http.Header, want int) []*http.Cookie {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test"+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if headers != nil {
			request.Header = headers.Clone()
		}
		request.Header.Set("Authorization", "Bearer unchanged-application")
		request.Header.Set("Forwarded", "for=203.0.113.9")
		request.Header.Set("X-Real-IP", "203.0.113.9")
		request.Header.Set("X-Forwarded-For", "203.0.113.9")
		request.Header.Set("X-Forwarded-Host", "untrusted.example")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		pendingHTTPResponse(t, response, want)
		protocol := 1
		if h2 {
			protocol = 2
		}
		if response.ProtoMajor != protocol || response.TLS == nil || !response.TLS.HandshakeComplete {
			t.Fatal("share sequence lost verified visitor TLS or its HTTP protocol")
		}
		return response.Cookies()
	}
	issued := visit("/__tnl/share/"+shareID+"."+secret, nil, http.StatusSeeOther)
	if len(issued) != 2 || capacity.Load() != 0 || forwarded.Load() != 0 || redemptions.Load() != 1 {
		t.Fatal("share preparation admitted application traffic")
	}
	headers := make(http.Header)
	if expiredCookie {
		// keep this exact expired cookie on both sides of revocation. the signed
		// share-backed bearer, not the raw share header, supplies permission.
		headers.Set(httpaccess.VisitorTokenHeader, permission.VisitorToken)
		headers.Set("Cookie", "app_session=ok; "+httpaccess.ShareCookieName+"=expired")
	} else {
		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatal(err)
		}
		request, _ := http.NewRequest(http.MethodGet, "https://preview.example.test/", nil)
		jar.SetCookies(request.URL, append(issued, &http.Cookie{Name: "app_session", Value: "ok", Path: "/"}))
		client.Jar = jar
	}
	visit("/api", headers, http.StatusNoContent)
	visit("/", headers, http.StatusNoContent)
	if forwarded.Load() != 2 || capacity.Load() != 1 || dials.Load() != 1 {
		t.Fatal("two share requests changed connection capacity or forwarding counts", forwarded.Load(), capacity.Load(), dials.Load())
	}
	// a reserved request joins the prior request guard on this sole connection
	// before the authority changes its revision.
	visit("/__tnl/revocation-barrier", nil, http.StatusNotFound)
	before := authority.Calls.Load()
	authority.revoked.Store(true)
	if err := policy.Refresh(t.Context()); err != nil {
		t.Fatal("refresh revoked share policy", err)
	}
	view, _, _ := policy.Lease().Current()
	if authority.Calls.Load() <= before || view.VisitorPolicyRevision != 2 {
		t.Fatal("revocation did not traverse the policy owner")
	}
	visit("/", headers, http.StatusForbidden)
	if forwarded.Load() != 2 || capacity.Load() != 1 || redemptions.Load() != 1 {
		t.Fatal("revoked share reached the application or repeated capacity/redemption")
	}
	if expiredCookie {
		if _, err := visitortoken.VerifyBearer(visitortoken.Token(permission.VisitorToken), view, time.Now()); !errors.Is(err, visitortoken.ErrToken) {
			t.Fatal("share's old bearer remained current after refresh", err)
		}
	}
}
