package controlapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type previewStoreStub struct {
	preview controlstate.Preview
	attach  controlstate.AddPreviewPublicURLRequest
}

func (s *previewStoreStub) CreatePreview(_ context.Context, teamID, identityID, _ string, _ time.Time) (controlstate.Preview, error) {
	s.preview = controlstate.Preview{ID: "pv_preview", TeamID: teamID, CreatedByIdentityID: identityID, PublicURLIDs: []string{}, CreatedAt: time.Now()}
	return s.preview, nil
}

func (s *previewStoreStub) GetPreview(_ context.Context, _ string) (controlstate.Preview, error) {
	return s.preview, nil
}

func (s *previewStoreStub) AddPreviewPublicURL(_ context.Context, request controlstate.AddPreviewPublicURLRequest, _ time.Time) (controlstate.Preview, error) {
	s.attach = request
	s.preview.PublicURLIDs = []string{request.PublicURLID}
	return s.preview, nil
}

func TestPreviewDoesNotCrossIdentityOrTeamBoundary(t *testing.T) {
	store := &previewStoreStub{}
	principal := testPublicURLReadPrincipal()
	h := &handler{previews: store, authorizer: &recordingAuthorizer{principal: principal}}
	for _, test := range []struct {
		team   string
		status int
	}{
		{"team_other", http.StatusNotFound},
		{"team_1", http.StatusCreated},
	} {
		request := httptest.NewRequest(http.MethodPost, "/v1/previews", strings.NewReader(`{"team_id":"`+test.team+`"}`))
		request.Header.Set("Authorization", "Bearer access-token")
		request.Header.Set("Idempotency-Key", "stable-worktree")
		response := httptest.NewRecorder()
		h.CreatePreview(response, request, controlv1.CreatePreviewParams{})
		if response.Code != test.status {
			t.Fatalf("team %s status = %d: %s", test.team, response.Code, response.Body.String())
		}
	}
	store.preview.CreatedByIdentityID = "someone-else"
	request := httptest.NewRequest(http.MethodGet, "/v1/previews/pv_preview", nil)
	request.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()
	h.GetPreview(response, request, "pv_preview")
	if response.Code != http.StatusNotFound {
		t.Fatalf("other identity read preview: %d %s", response.Code, response.Body.String())
	}
}

func TestPreviewAttachmentAuthorizesTheExistingPublicURL(t *testing.T) {
	preview := &previewStoreStub{preview: controlstate.Preview{
		ID: "pv_preview", TeamID: "team_1", CreatedByIdentityID: "identity_1",
	}}
	routes := &publicURLMutationStoreStub{route: controlstate.PublicURL{
		ID: "url_1", TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
		CanonicalHostname: "web.example.test", Target: "http://127.0.0.1:3000",
		PublicURLScope: controlstate.PublicURLScopeMember, MutationRevision: 3,
		AllowedIPPrefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}}
	authorizer := &recordingAuthorizer{principal: testPublicURLReadPrincipal(), decision: authorization.Decision{
		IdentityID: "identity_1", TeamID: "team_1", PolicyRevision: 7,
		PublicURLMembershipID: "membership_1", DomainID: "domain_1",
		CanonicalHostname: "web.example.test", PublicURLScope: authorization.PublicURLScopeMember,
	}}
	h := &handler{store: routes, previews: preview, authorizer: authorizer}
	request := httptest.NewRequest(http.MethodPost, "/v1/previews/pv_preview/public-urls", strings.NewReader(`{"public_url_id":"url_1"}`))
	request.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()
	h.AddPreviewPublicURL(response, request, "pv_preview")
	if response.Code != http.StatusOK || preview.attach.PreviewID != "pv_preview" || preview.attach.PublicURLID != "url_1" ||
		preview.attach.IdentityID != "identity_1" || preview.attach.ExpectedMutationRevision != 3 ||
		len(authorizer.requests) != 1 || authorizer.requests[0].Operation != authorization.OperationPublicURLUpdate ||
		authorizer.requests[0].PublicURLMembershipID != "membership_1" || authorizer.requests[0].AllowedIPPrefixes[0] != "192.0.2.0/24" {
		t.Fatalf("attachment = %+v, authorization = %+v, response = %d %s", preview.attach, authorizer.requests, response.Code, response.Body.String())
	}
}
