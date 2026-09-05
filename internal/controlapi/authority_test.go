package controlapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func TestCreateTeamHandlerAuthenticatesAndPreservesIdempotency(t *testing.T) {
	createdAt := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	store := &authorityMutationStoreStub{team: controlstate.Team{
		ID: "team_1", Kind: "organization", DisplayName: "Example team", ManagedLabel: "quiet-lake",
		DefaultDomainID: "domain_1", PolicyRevision: 1, CreatedAt: createdAt, UpdatedAt: createdAt,
	}}
	handler := NewHandler(Config{}, store, nil)
	request := httptest.NewRequest(http.MethodPost, "/v1/teams", bytes.NewBufferString(`{
		"display_name":"Example team",
		"member_slug":"member"
	}`))
	request.Header.Set("Authorization", "Bearer access-token")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "create-team-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	if store.createTeam.IdentityID != "identity_1" || store.createTeam.IdempotencyKey != "create-team-1" ||
		store.createTeam.DisplayName != "Example team" || store.createTeam.MemberSlug != "member" ||
		store.createTeam.RequestDigest == ([32]byte{}) {
		t.Fatalf("create team request = %#v", store.createTeam)
	}
	var body authorityv1.Team
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Id != "team_1" || body.Kind != authorityv1.Organization || body.DefaultDomainId != "domain_1" {
		t.Fatalf("create team response = %#v", body)
	}
}

func TestCreateTeamHandlerMapsAuthorityConflict(t *testing.T) {
	store := &authorityMutationStoreStub{createTeamError: controlstate.ErrAuthorityIdempotency}
	handler := NewHandler(Config{}, store, nil)
	request := httptest.NewRequest(http.MethodPost, "/v1/teams", bytes.NewBufferString(`{
		"display_name":"Example team",
		"member_slug":"member"
	}`))
	request.Header.Set("Authorization", "Bearer access-token")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "create-team-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusConflict, response.Body.String())
	}
}

type authorityMutationStoreStub struct {
	Store
	team            controlstate.Team
	createTeam      controlstate.CreateTeamRequest
	createTeamError error
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
