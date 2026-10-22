package authority

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/oidc"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
)

type teamUsageVerifier struct {
	identity oidc.Identity
	err      error
}

func (v teamUsageVerifier) Verify(context.Context, string) (oidc.Identity, error) {
	return v.identity, v.err
}

type teamUsageStoreStub struct {
	Store
	err         error
	calls       int
	team, actor string
}

func (s *teamUsageStoreStub) ResolveCompanyAccount(context.Context, string, string) (string, error) {
	return "ident_actor", nil
}

func (s *teamUsageStoreStub) AuthorizeWebsiteTeamUsage(_ context.Context, team, actor string, _ time.Time) error {
	s.calls++
	s.team, s.actor = team, actor
	return s.err
}

func TestWebsiteTeamUsageBoundary(t *testing.T) {
	const target = "/v1/service/teams/tm_1111111111111111111111/usage-authorization"
	const secret = "website-service-secret-012345678901"
	privateCause := errors.New("private state or provider detail")
	for _, test := range []struct {
		name                     string
		state, verifier          error
		query, signedQuery, body string
		credential               string
		status, calls            int
		code                     string
	}{
		{name: "allowed", credential: secret, status: 204, calls: 1},
		{name: "bound raw query", query: "?q=a%20b&n=2", signedQuery: "?q=a%20b&n=2", credential: secret, status: 204, calls: 1},
		{name: "query substitution", query: "?n=2&q=a%20b", signedQuery: "?q=a%20b&n=2", credential: secret, status: 401, code: "unauthenticated"},
		{name: "body substitution", body: "private body", credential: secret, status: 400, code: "invalid_request"},
		{name: "website credential required", status: 401, code: "unauthenticated"},
		{name: "membership denied", state: fmt.Errorf("wrapped: %w", controlstate.ErrAuthorityAccess), credential: secret, status: 403, calls: 1, code: "forbidden"},
		{name: "source denied", state: fmt.Errorf("wrapped: %w", controlstate.ErrServiceSourceSignInRequired), credential: secret, status: 403, calls: 1, code: "source_sign_in_required"},
		{name: "replay denied", state: fmt.Errorf("wrapped: %w", controlstate.ErrOIDCAssertionReplay), credential: secret, status: 401, calls: 1, code: "unauthenticated"},
		{name: "provider unavailable", verifier: errors.Join(oidc.ErrUnavailable, privateCause), credential: secret, status: 503, code: "unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := &teamUsageStoreStub{err: test.state}
			v := teamUsageVerifier{identity: oidc.Identity{Issuer: "https://account.example", ClientID: "tnl-control", Subject: "sam", Nonce: controlstate.TeamUsageActorNonce(http.MethodGet, target+test.signedQuery, nil)}, err: test.verifier}
			h := testHandler(t, Config{ControlURL: "https://control.example", OIDCIssuer: "https://account.example", OIDCClientID: "tnl-control", OIDCScopes: []string{"openid"}, OIDCVerifier: v, WebServiceSecret: secret}, s)
			r := httptest.NewRequest(http.MethodGet, target+test.query, strings.NewReader(test.body))
			r.Header.Set("Authorization", "Bearer "+test.credential)
			r.Header.Set("X-Tnl-Actor-Token", "private assertion")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != test.status || s.calls != test.calls {
				t.Fatalf("status=%d calls=%d: %s", w.Code, s.calls, w.Body)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("authorization must not be cached")
			}
			if test.code != "" && !strings.Contains(w.Body.String(), `"code":"`+test.code+`"`) {
				t.Fatal(w.Body.String())
			}
			if strings.Contains(w.Body.String(), privateCause.Error()) || strings.Contains(w.Body.String(), "private assertion") || strings.Contains(w.Body.String(), "private body") {
				t.Fatal("unsafe problem output")
			}
			if s.calls > 0 && (s.team != "tm_1111111111111111111111" || s.actor != "ident_actor") {
				t.Fatal("wrong actor/team")
			}
		})
	}
}
