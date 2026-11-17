package public

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type previewStoreStub struct {
	preview controlstate.Preview
	attach  controlstate.AddPreviewServiceRequest
}

func (s *previewStoreStub) ListPreviews(context.Context, string, string, string) (controlstate.PreviewPage, error) {
	return controlstate.PreviewPage{Previews: []controlstate.PreviewSummary{{ID: s.preview.ID}}}, nil
}

func (s *previewStoreStub) CreatePreview(_ context.Context, teamID, identityID, _ string, _ time.Time) (controlstate.Preview, error) {
	s.preview = controlstate.Preview{ID: "pv_preview", TeamID: teamID, CreatedByIdentityID: identityID, ServiceIDs: []string{}, CreatedAt: time.Now()}
	return s.preview, nil
}

func (s *previewStoreStub) GetPreview(_ context.Context, _ string) (controlstate.Preview, error) {
	return s.preview, nil
}

func (s *previewStoreStub) AddPreviewService(_ context.Context, request controlstate.AddPreviewServiceRequest, _ time.Time) (controlstate.Preview, error) {
	s.attach = request
	s.preview.ServiceIDs = []string{request.ServiceID}
	return s.preview, nil
}

func TestPreviewDoesNotCrossIdentityOrTeamBoundary(t *testing.T) {
	store := &previewStoreStub{}
	principal := testControlReadPrincipal()
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

func TestPreviewAttachmentPassesAuthenticatedServiceScopeToState(t *testing.T) {
	preview := &previewStoreStub{preview: controlstate.Preview{
		ID: "pv_preview", TeamID: "team_1", CreatedByIdentityID: "identity_1",
	}}
	authorizer := &recordingAuthorizer{principal: testControlReadPrincipal()}
	h := &handler{previews: preview, authorizer: authorizer}
	request := httptest.NewRequest(http.MethodPost, "/v1/previews/pv_preview/services", strings.NewReader(`{"service_id":"svc_`+strings.Repeat("A", 22)+`"}`))
	request.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()
	h.AddPreviewService(response, request, "pv_preview")
	if response.Code != http.StatusOK || preview.attach.PreviewID != "pv_preview" || preview.attach.ServiceID != "svc_"+strings.Repeat("A", 22) ||
		preview.attach.IdentityID != "identity_1" || preview.attach.TeamID != "team_1" {
		t.Fatalf("attachment = %+v, response = %d %s", preview.attach, response.Code, response.Body.String())
	}
}
