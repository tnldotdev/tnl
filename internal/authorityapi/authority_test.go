package authorityapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlapi"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func TestCreateTeamAuthenticatesAndPreservesIdempotency(t *testing.T) {
	s := &authorityMutationStoreStub{team: controlstate.Team{ID: "team_1", Kind: "organization", DisplayName: "studio"}}
	w := httptest.NewRecorder()
	testHandler(t, Config{}, s).ServeHTTP(w, newCreateTeamRequest())
	if w.Code != 201 || s.createTeam.IdentityID != "identity_1" || s.createTeam.IdempotencyKey != "create-team-1" || s.createTeam.DisplayName != "studio" || s.createTeam.MemberSlug != "member" || s.createTeam.RequestDigest == ([32]byte{}) {
		t.Fatalf("create: %d %#v", w.Code, s.createTeam)
	}
}

func TestTeamCreationFailures(t *testing.T) {
	for _, tt := range []struct {
		err    error
		status int
		code   authorityv1.ProblemCode
	}{
		{controlstate.ErrAuthorityIdempotency, 409, authorityv1.Conflict},
		{controlstate.ErrTeamNameUnavailable, 409, authorityv1.NameUnavailable},
		{controlstate.ErrMemberSlugRequired, 400, authorityv1.InvalidRequest},
	} {
		t.Run(string(tt.code), func(t *testing.T) {
			w := httptest.NewRecorder()
			testHandler(t, Config{}, &authorityMutationStoreStub{createTeamError: tt.err}).ServeHTTP(w, newCreateTeamRequest())
			var p authorityv1.Problem
			if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || w.Code != tt.status || p.Code != tt.code {
				t.Fatalf("failure: %d %s", w.Code, w.Body)
			}
		})
	}
}

func TestDomainClaimRequiresAutomationAndOptIn(t *testing.T) {
	for _, tt := range []struct {
		config Config
		status int
	}{{Config{CustomDomainsEnabled: true}, 503}, {Config{DNSAutomation: true}, 403}} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/v1/teams/team_1/domains", strings.NewReader(`{"domain":"custom.example.test"}`))
		r.Header.Set("Authorization", "Bearer access")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "claim")
		testHandler(t, tt.config, &authorityMutationStoreStub{}).ServeHTTP(w, r)
		if w.Code != tt.status {
			t.Fatalf("claim: %d %s", w.Code, w.Body)
		}
	}
}

func TestAuthorityCompositionAndRetiredHumanExchanges(t *testing.T) {
	mux, err := controlapi.NewHandler(controlapi.Config{}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := Register(mux, Config{}, &authorityMutationStoreStub{})
	if err != nil {
		t.Fatal(err)
	}
	if !routes.Matches("GET /v1/teams") || routes.Matches("GET /v1/health") {
		t.Fatal(routes)
	}
	for _, path := range []string{"/v1/auth/token", "/v1/auth/oidc", "/v1/auth/browser", "/v1/service/authorize"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("POST", path, nil))
		if w.Code != 404 {
			t.Fatalf("retired endpoint %s: %d", path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/v1/health", nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
}

func newCreateTeamRequest() *http.Request {
	r := httptest.NewRequest("POST", "/v1/teams", strings.NewReader(`{"display_name":"studio","member_slug":"member"}`))
	r.Header.Set("Authorization", "Bearer access-token")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", "create-team-1")
	return r
}

type authorityMutationStoreStub struct {
	Store
	team            controlstate.Team
	createTeam      controlstate.CreateTeamRequest
	createTeamError error
}

func (s *authorityMutationStoreStub) AuthorizeTeamSession(_ context.Context, p controlstate.ControlPrincipal, team string, _ time.Time) error {
	if p.IdentityID != "identity_1" || team != "team_1" {
		return controlstate.ErrAuthorityAccess
	}
	return nil
}

func (s *authorityMutationStoreStub) AuthenticateAccessToken(
	context.Context,
	credentials.AccessToken,
	time.Time,
) (controlstate.ControlPrincipal, error) {
	return controlstate.ControlPrincipal{IdentityID: "identity_1"}, nil
}
func (s *authorityMutationStoreStub) CreateTeam(_ context.Context, r controlstate.CreateTeamRequest, _ time.Time) (controlstate.Team, error) {
	s.createTeam = r
	return s.team, s.createTeamError
}
