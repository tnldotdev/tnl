package authorityapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
)

type feedbackPolicyStoreStub struct {
	*authorityAuthenticationStub
	policy         controlstate.TeamFeedbackPolicy
	err            error
	identity, team string
	reads, writes  int
}

func (s *feedbackPolicyStoreStub) GetTeamFeedbackPolicy(_ context.Context, identity, team string) (controlstate.TeamFeedbackPolicy, error) {
	s.identity, s.team = identity, team
	s.reads++
	return s.policy, s.err
}

func (s *feedbackPolicyStoreStub) SetTeamFeedbackPolicy(_ context.Context, identity, team string, required bool, _ time.Time) (controlstate.TeamFeedbackPolicy, error) {
	s.identity, s.team = identity, team
	s.writes++
	s.policy.RequireSignIn = required
	return s.policy, s.err
}

func TestTeamFeedbackPolicyAuthorityContract(t *testing.T) {
	for _, test := range []struct {
		name, method, body, auth string
		browser                  bool
		err                      error
		status, writes           int
	}{
		{"read", "GET", "", "Bearer exact-access-token", false, nil, 200, 0},
		{"enable", "PUT", `{"require_sign_in":true}`, "Bearer exact-access-token", true, nil, 200, 1},
		{"disable without OIDC", "PUT", `{"require_sign_in":false}`, "Bearer exact-access-token", false, nil, 200, 1},
		{"enable without OIDC", "PUT", `{"require_sign_in":true}`, "Bearer exact-access-token", false, nil, 503, 0},
		{"member edit", "PUT", `{"require_sign_in":true}`, "Bearer exact-access-token", true, controlstate.ErrAuthorityAccess, 403, 1},
		{"member disable without OIDC", "PUT", `{"require_sign_in":false}`, "Bearer exact-access-token", false, controlstate.ErrAuthorityAccess, 403, 1},
		{"nonmember read", "GET", "", "Bearer exact-access-token", false, controlstate.ErrTeamNotFound, 404, 0},
		{"unauthenticated", "PUT", `{"require_sign_in":true}`, "", true, nil, 401, 0},
		{"missing", "PUT", `{}`, "Bearer exact-access-token", true, nil, 400, 0},
		{"null field", "PUT", `{"require_sign_in":null}`, "Bearer exact-access-token", true, nil, 400, 0},
		{"null body", "PUT", `null`, "Bearer exact-access-token", true, nil, 400, 0},
		{"wrong type", "PUT", `{"require_sign_in":"true"}`, "Bearer exact-access-token", true, nil, 400, 0},
		{"unknown field", "PUT", `{"require_sign_in":true,"issuer":"secret-issuer"}`, "Bearer exact-access-token", true, nil, 400, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &feedbackPolicyStoreStub{authorityAuthenticationStub: newAuthorityAuthenticationStub(), err: test.err}
			cfg := Config{LoginToken: testLoginToken, OIDCIssuer: "secret-issuer"}
			if test.browser {
				cfg.BrowserOIDCVerifier = oidcVerifierStub{}
			}
			response := serveAuthorityMutation(testHandler(t, cfg, store), test.method, "/v1/teams/team_path/feedback-policy", test.body, test.auth, "")
			if response.Code != test.status || store.writes != test.writes || strings.Contains(response.Body.String(), "secret-issuer") {
				t.Fatalf("response=%d %s writes=%d", response.Code, response.Body.String(), store.writes)
			}
			if store.reads+store.writes > 0 && (store.identity != "identity_actor" || store.team != "team_path") {
				t.Fatalf("scope=%s/%s", store.identity, store.team)
			}
			if test.status == 200 && !strings.Contains(response.Body.String(), `"require_sign_in":`) {
				t.Fatalf("response shape=%s", response.Body.String())
			}
		})
	}
}
