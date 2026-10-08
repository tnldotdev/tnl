package authorityapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlapi"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const testLoginToken = "tnl_login_AAECAwQFBgcICQoLDA0ODw.EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8"

func TestNewHandlerRejectsInvalidLoginToken(t *testing.T) {
	if _, err := NewHandler(Config{LoginToken: "invalid"}, nil); err == nil {
		t.Fatal("invalid login token accepted")
	}
}

func TestCreateTeamHandlerAuthenticatesAndPreservesIdempotency(t *testing.T) {
	createdAt := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	store := &authorityMutationStoreStub{team: controlstate.Team{
		ID: "team_1", Kind: "organization", DisplayName: "studio", ManagedLabel: "quiet-lake",
		DefaultDomainID: "domain_1", PolicyRevision: 1, CreatedAt: createdAt, UpdatedAt: createdAt,
	}}
	handler := testHandler(t, Config{}, store)
	request := newCreateTeamRequest()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("content type = %q", response.Header().Get("Content-Type"))
	}
	if store.createTeam.IdentityID != "identity_1" || store.createTeam.IdempotencyKey != "create-team-1" ||
		store.createTeam.DisplayName != "studio" || store.createTeam.MemberSlug != "member" ||
		store.createTeam.RequestDigest == ([32]byte{}) {
		t.Fatalf("create team request = %#v", store.createTeam)
	}
	var body authorityv1.Team
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Id != "team_1" || body.Kind != authorityv1.Organization || body.DefaultDomainId != "domain_1" || body.DisplayName != "studio" {
		t.Fatalf("create team response = %#v", body)
	}
}

func TestCreateTeamHandlerMapsAuthorityConflict(t *testing.T) {
	store := &authorityMutationStoreStub{createTeamError: controlstate.ErrAuthorityIdempotency}
	handler := testHandler(t, Config{}, store)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, newCreateTeamRequest())
	if response.Code != http.StatusConflict || response.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusConflict, response.Body.String())
	}
	var problem authorityv1.Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil || problem.Code != authorityv1.Conflict {
		t.Fatalf("problem = %#v, %v", problem, err)
	}
}

func TestCreateTeamHandlerReportsUnavailableName(t *testing.T) {
	store := &authorityMutationStoreStub{createTeamError: controlstate.ErrTeamNameUnavailable}
	response := httptest.NewRecorder()
	testHandler(t, Config{}, store).ServeHTTP(response, newCreateTeamRequest())
	var problem authorityv1.Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil || response.Code != http.StatusConflict ||
		problem.Code != authorityv1.NameUnavailable || problem.Title != "team name unavailable" {
		t.Fatalf("name conflict response = %d, %#v, %v", response.Code, problem, err)
	}
}

func TestCreateTeamHandlerExplainsMissingMemberSlug(t *testing.T) {
	store := &authorityMutationStoreStub{createTeamError: controlstate.ErrMemberSlugRequired}
	response := httptest.NewRecorder()
	testHandler(t, Config{}, store).ServeHTTP(response, newCreateTeamRequest())
	var problem authorityv1.Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil || response.Code != http.StatusBadRequest ||
		problem.Code != authorityv1.InvalidRequest || !strings.Contains(problem.Title, "member_slug") {
		t.Fatalf("missing member slug response = %d, %#v, %v", response.Code, problem, err)
	}
}

func TestClaimTeamDomainRequiresDNSAutomation(t *testing.T) {
	store := &authorityMutationStoreStub{}
	handler := testHandler(t, Config{CustomDomainsEnabled: true}, store)
	request := httptest.NewRequest(
		http.MethodPost, "/v1/teams/team_1/domains", strings.NewReader(`{"domain":"claim.example.test"}`),
	)
	request.Header.Set("Authorization", "Bearer access-token")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "claim")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), `"code":"unavailable"`) {
		t.Fatalf("domain claim without DNS automation = %d: %s", response.Code, response.Body.String())
	}
}

func TestCustomDomainClaimsRequireExplicitOptIn(t *testing.T) {
	store := &authorityMutationStoreStub{}
	handler := testHandler(t, Config{DNSAutomation: true}, store)
	request := httptest.NewRequest(http.MethodPost, "/v1/teams/team_1/domains", strings.NewReader(`{"domain":"custom.example.test"}`))
	request.Header.Set("Authorization", "Bearer access-token")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "custom")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var problem authorityv1.Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil || response.Code != http.StatusForbidden || problem.Code != authorityv1.CustomDomainsDisabled {
		t.Fatalf("custom domain claim without opt-in = %d: %s", response.Code, response.Body.String())
	}
}

func TestExchangeLoginTokenUsesVerifierSourceRevision(t *testing.T) {
	store := &authorityMutationStoreStub{}
	handler := testHandler(t, Config{LoginToken: testLoginToken}, store)
	request := httptest.NewRequest(
		http.MethodPost, "/v1/auth/token", strings.NewReader(`{"login_token":"`+testLoginToken+`"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	verifier, err := credentials.ParseLoginToken(credentials.LoginToken(testLoginToken))
	if err != nil {
		t.Fatal(err)
	}
	if store.loginSourceRevision != verifier.SourceRevision() {
		t.Fatalf("login source revision = %d, want %d", store.loginSourceRevision, verifier.SourceRevision())
	}
}

func TestExchangeLoginTokenMapsSessionCreationFailureToUnavailable(t *testing.T) {
	store := &authorityMutationStoreStub{builtinError: controlstate.ErrControlAuthentication}
	handler := testHandler(t, Config{LoginToken: testLoginToken}, store)
	request := httptest.NewRequest(
		http.MethodPost, "/v1/auth/token", strings.NewReader(`{"login_token":"`+testLoginToken+`"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
}

func TestExchangeOIDCTokenCreatesLocalSession(t *testing.T) {
	digest := sha256.Sum256([]byte("id-token"))
	verified := oidcauth.Identity{
		Issuer: "https://issuer.example", Subject: "auth0|subject", DisplayName: "Example User",
		NormalizedEmail: "user@example.com", EmailVerified: true,
		ExpiresAt: time.Now().Add(time.Hour), AssertionDigest: digest,
	}
	store := &authorityMutationStoreStub{}
	handler := testHandler(t, Config{
		ManagedDeploymentDomain: "example.test", OIDCVerifier: oidcVerifierStub{identity: verified},
		AccessTokenLifetime: time.Hour, RefreshTokenLifetime: 24 * time.Hour,
	}, store)
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/oidc", strings.NewReader(`{"id_token":"id-token"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if store.oidcManagedDomain != "example.test" || store.oidcIdentity.Issuer != verified.Issuer ||
		store.oidcIdentity.Subject != verified.Subject || store.oidcIdentity.AssertionDigest != digest {
		t.Fatalf("OIDC session request = %q, %#v", store.oidcManagedDomain, store.oidcIdentity)
	}
}

func TestExchangeOIDCTokenMapsAuthenticationFailures(t *testing.T) {
	for _, test := range []struct {
		name     string
		verifier oidcauth.Verifier
		storeErr error
		status   int
	}{
		{name: "not configured", status: http.StatusNotFound},
		{name: "invalid token", verifier: oidcVerifierStub{err: oidcauth.ErrUnauthenticated}, status: http.StatusUnauthorized},
		{name: "provider unavailable", verifier: oidcVerifierStub{err: oidcauth.ErrUnavailable}, status: http.StatusServiceUnavailable},
		{name: "replayed token", verifier: oidcVerifierStub{identity: validOIDCTestIdentity()}, storeErr: controlstate.ErrOIDCAssertionReplay, status: http.StatusUnauthorized},
		{name: "store unavailable", verifier: oidcVerifierStub{identity: validOIDCTestIdentity()}, storeErr: errors.New("database unavailable"), status: http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &authorityMutationStoreStub{oidcError: test.storeErr}
			handler := testHandler(t, Config{OIDCVerifier: test.verifier, AccessTokenLifetime: time.Hour, RefreshTokenLifetime: 24 * time.Hour}, store)
			request := httptest.NewRequest(http.MethodPost, "/v1/auth/oidc", strings.NewReader(`{"id_token":"id-token"}`))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.status, response.Body.String())
			}
		})
	}
}

func TestRegisterComposesAuthorityAndControlRoutesOnOneMux(t *testing.T) {
	store := &authorityMutationStoreStub{team: controlstate.Team{ID: "team_1", Kind: "organization"}}
	mux, err := controlapi.NewHandler(controlapi.Config{}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	routes, err := Register(mux, Config{}, store)
	if err != nil {
		t.Fatal(err)
	}
	if !routes.Matches("GET /v1/teams") || routes.Matches("GET /v1/health") {
		t.Fatalf("registered authority routes = %v", routes)
	}

	health := httptest.NewRecorder()
	mux.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("control health status = %d: %s", health.Code, health.Body.String())
	}
	var healthBody controlv1.HealthResponse
	if err := json.Unmarshal(health.Body.Bytes(), &healthBody); err != nil || healthBody.Status != controlv1.HealthResponseStatusOk {
		t.Fatalf("control health = %#v, %v", healthBody, err)
	}

	created := httptest.NewRecorder()
	mux.ServeHTTP(created, newCreateTeamRequest())
	if created.Code != http.StatusCreated {
		t.Fatalf("authority create team status = %d: %s", created.Code, created.Body.String())
	}
}

func TestBuiltinAuthorityDoesNotExposeHostedServiceAuthorization(t *testing.T) {
	handler := testHandler(t, Config{}, &authorityMutationStoreStub{})
	for _, path := range []string{"/v1/service/authorize", "/not-an-api"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
		if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), `"code":"not_found"`) {
			t.Fatalf("%s = %d: %s", path, response.Code, response.Body.String())
		}
	}
}

func newCreateTeamRequest() *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/v1/teams", bytes.NewBufferString(`{
		"display_name":"studio",
		"member_slug":"member"
	}`))
	request.Header.Set("Authorization", "Bearer access-token")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "create-team-1")
	return request
}

type authorityMutationStoreStub struct {
	Store
	team                controlstate.Team
	createTeam          controlstate.CreateTeamRequest
	createTeamError     error
	loginSourceRevision int64
	builtinError        error
	oidcManagedDomain   string
	oidcIdentity        controlstate.OIDCIdentity
	oidcError           error
}

type oidcVerifierStub struct {
	identity oidcauth.Identity
	err      error
}

func (s oidcVerifierStub) Verify(context.Context, string) (oidcauth.Identity, error) {
	return s.identity, s.err
}

func validOIDCTestIdentity() oidcauth.Identity {
	return oidcauth.Identity{
		Issuer: "https://issuer.example", Subject: "subject", DisplayName: "Example User",
		ExpiresAt: time.Now().Add(time.Hour), AssertionDigest: sha256.Sum256([]byte("id-token")),
	}
}

func (s *authorityMutationStoreStub) AuthenticateAccessToken(
	context.Context,
	credentials.AccessToken,
	int64,
	time.Time,
) (controlstate.ControlPrincipal, error) {
	return controlstate.ControlPrincipal{IdentityID: "identity_1"}, nil
}

func (s *authorityMutationStoreStub) CreateTeam(
	_ context.Context,
	request controlstate.CreateTeamRequest,
	_ time.Time,
) (controlstate.Team, error) {
	s.createTeam = request
	return s.team, s.createTeamError
}

func (s *authorityMutationStoreStub) CreateBuiltinControlSession(
	_ context.Context,
	_ string,
	sourceRevision int64,
	_, _ time.Duration,
	_ time.Time,
) (controlstate.ControlSession, error) {
	s.loginSourceRevision = sourceRevision
	return controlstate.ControlSession{}, s.builtinError
}

func (s *authorityMutationStoreStub) CreateOIDCControlSession(
	_ context.Context,
	managedDomain string,
	identity controlstate.OIDCIdentity,
	_, _ time.Duration,
	_ time.Time,
) (controlstate.ControlSession, error) {
	s.oidcManagedDomain = managedDomain
	s.oidcIdentity = identity
	return controlstate.ControlSession{}, s.oidcError
}
