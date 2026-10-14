package controlapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type namedInvitationStoreStub struct {
	created controlstate.CreateVisitorShareInvitationRequest
}

func (s *namedInvitationStoreStub) CreateVisitorShareInvitation(_ context.Context, request controlstate.CreateVisitorShareInvitationRequest, now time.Time) (controlstate.VisitorShareInvitation, error) {
	s.created = request
	return controlstate.VisitorShareInvitation{ID: "shr_0123456789abcdefghijkl", TeamID: request.TeamID, PublicURLID: request.PublicURLID,
		Email: request.Email, CreatedByIdentityID: request.ActingIdentityID, CreatedAt: now, ExpiresAt: request.ExpiresAt}, nil
}

func (s *namedInvitationStoreStub) AcceptVisitorShareInvitation(_ context.Context, _, _ string, _ time.Time) (controlstate.VisitorShareInvitation, error) {
	return controlstate.VisitorShareInvitation{}, nil
}

func (s *namedInvitationStoreStub) ListVisitorShareInvitations(_ context.Context, _, _, _ string) (controlstate.VisitorShareInvitationPage, error) {
	return controlstate.VisitorShareInvitationPage{}, nil
}

func (s *namedInvitationStoreStub) GetVisitorShareInvitation(_ context.Context, _ string) (controlstate.VisitorShareInvitation, error) {
	return controlstate.VisitorShareInvitation{}, nil
}

func (s *namedInvitationStoreStub) RevokeVisitorShareInvitation(_ context.Context, _, _, _ string, _ time.Time) (controlstate.VisitorShareInvitation, error) {
	return controlstate.VisitorShareInvitation{}, nil
}

func TestNamedInviteRequiresOwnerAndDoesNotEchoSecretDigest(t *testing.T) {
	routes := &publicURLMutationStoreStub{route: controlstate.PublicURL{
		ID: "url_0123456789abcdefghijkl", TeamID: "team_1", DomainID: "dom_1", MembershipID: "mem_1",
		CanonicalHostname: "web.example.test", ServiceProtocol: controlstate.PublicURLServiceHTTP,
		Purpose: controlstate.PublicURLPurposeApp, PublicURLScope: controlstate.PublicURLScopeMember,
		LifecycleState: controlstate.PublicURLLifecycleEnabled, MutationRevision: 3,
	}}
	invites := &namedInvitationStoreStub{}
	authorizer := &recordingAuthorizer{principal: testPublicURLReadPrincipal(), decision: authorization.Decision{
		IdentityID: "identity_1", TeamID: "team_1", PolicyRevision: 7,
	}}
	h := &handler{store: routes, visitorInvitations: invites, authorizer: authorizer, config: Config{BrowserOIDCClientID: "browser-client"}}
	fingerprint := sha256.Sum256([]byte("invite secret"))
	create := func(team string) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"team_id":%q,"public_url_id":"url_0123456789abcdefghijkl","email":"sam@example.test","expires_at":%q,"secret_fingerprint":%q}`,
			team, time.Now().UTC().Add(time.Hour).Format(time.RFC3339), hex.EncodeToString(fingerprint[:]))
		request := httptest.NewRequest(http.MethodPost, "/v1/shares/invitations", strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer access-token")
		request.Header.Set("Idempotency-Key", "invite-sam")
		response := httptest.NewRecorder()
		h.CreateVisitorInvitation(response, request, controlv1.CreateVisitorInvitationParams{})
		return response
	}
	if response := create("team_other"); response.Code != http.StatusNotFound || invites.created.PublicURLID != "" {
		t.Fatalf("another team's invite = %d %s", response.Code, response.Body.String())
	}
	response := create("team_1")
	if response.Code != http.StatusCreated || invites.created.ActingIdentityID != "identity_1" ||
		invites.created.ExpectedMutationRevision != routes.route.MutationRevision || len(authorizer.requests) != 1 ||
		authorizer.requests[0].Operation != authorization.OperationShareCreate ||
		strings.Contains(response.Body.String(), hex.EncodeToString(fingerprint[:])) || strings.Contains(response.Body.String(), "secret_fingerprint") {
		t.Fatalf("named invite = %d %s, request=%+v, authorization=%+v", response.Code, response.Body.String(), invites.created, authorizer.requests)
	}
}
