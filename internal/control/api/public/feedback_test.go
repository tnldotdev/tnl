package public

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type feedbackStoreStub struct {
	FeedbackStore
	thread                  controlstate.FeedbackThread
	pageURL                 string
	managedService, manager string
}

func TestFeedbackInputsExcludeOutputOnlyAndReviewerUpdateEvents(t *testing.T) {
	h := &handler{}
	owner := httptest.NewRecorder()
	h.AppendFeedbackEvent(owner, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"type":"thread.created"}`)), "fb_example", controlv1.AppendFeedbackEventParams{})
	if owner.Code != http.StatusBadRequest {
		t.Fatal("owner accepted an output-only event")
	}
	reviewer := httptest.NewRecorder()
	h.AppendReviewerFeedbackEvent(reviewer, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"run_number":"1","type":"update","access":{}}`)), "svc_example", "srun_example", "fb_example", controlv1.AppendReviewerFeedbackEventParams{})
	if reviewer.Code != http.StatusBadRequest {
		t.Fatal("reviewer accepted an implementer update")
	}
}

func (s *feedbackStoreStub) GetFeedback(_ context.Context, _ string) (controlstate.FeedbackThread, error) {
	return s.thread, nil
}

func (s *feedbackStoreStub) ReviewerFeedbackScope(_ context.Context, _ controlstate.ServiceHTTPRun, _ string, _ controlstate.FeedbackActor, _ time.Time) (string, string, error) {
	return s.thread.TeamID, s.pageURL, nil
}

func (s *feedbackStoreStub) ListFeedbackForTeam(_ context.Context, _, _ string) (controlstate.FeedbackThreadPage, error) {
	return controlstate.FeedbackThreadPage{Threads: []controlstate.FeedbackThread{s.thread}, EventCursor: 3}, nil
}

func (s *feedbackStoreStub) AuthorizeFeedbackService(_ context.Context, service, actor string, _ time.Time) error {
	s.managedService, s.manager = service, actor
	return nil
}

func feedbackTestThread() controlstate.FeedbackThread {
	return controlstate.FeedbackThread{
		ID: "fb_0123456789abcdefghijkl", PreviewID: "pv_0123456789abcdefghijkl",
		TeamID: "team_1", ServiceID: "svc_1", ServiceRunID: "srun_1", RunNumber: 2,
		PagePath: "/settings", Service: "web", State: controlstate.FeedbackOpen,
		SchemaVersion: 1, MessageCount: 1, ReportText: "Save does nothing",
		Evidence:       json.RawMessage(`{"schema_version":1,"actions":[],"failed_requests":[]}`),
		SourceAtReport: json.RawMessage(`{"schema_version":1,"head_commit":"","project_path":"","branch":"","changed_files":[],"complete":false}`),
		CreatedAt:      time.Now().UTC(), StateUpdatedAt: time.Now().UTC(),
	}
}

func TestFeedbackOwnerReadsOnlyManageableServiceThreads(t *testing.T) {
	thread := feedbackTestThread()
	store := &feedbackStoreStub{thread: thread}
	authorizer := &recordingAuthorizer{principal: testControlReadPrincipal()}
	h := &handler{feedback: store, authorizer: authorizer}
	request := httptest.NewRequest(http.MethodGet, "/v1/feedback/"+thread.ID, nil)
	request.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()
	h.GetFeedbackThread(response, request, thread.ID)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"text":"Save does nothing"`) ||
		store.managedService != thread.ServiceID || store.manager != "identity_1" {
		t.Fatalf("feedback read = %d %s", response.Code, response.Body.String())
	}
	authorizer.principal.teamIDs = map[string]struct{}{"team_other": {}}
	denied := httptest.NewRecorder()
	h.GetFeedbackThread(denied, request, thread.ID)
	if denied.Code != http.StatusNotFound || strings.Contains(denied.Body.String(), "Save does nothing") {
		t.Fatalf("unrelated team read private feedback: %d %s", denied.Code, denied.Body.String())
	}
}

func TestReviewerFeedbackReadCannotCrossService(t *testing.T) {
	thread := feedbackTestThread()
	store := &feedbackStoreStub{thread: thread, pageURL: thread.ServiceID}
	h := &handler{feedback: store, dependencies: Stores{ServiceHTTP: &serviceBrowserHandoffStore{}}}
	request := httptest.NewRequest(http.MethodPost, "/v1/services/svc_other/runs/srun_other/feedback/"+thread.ID+"/query",
		strings.NewReader(`{"run_number":"1","preview_id":"pv_0123456789abcdefghijkl","access":{"visit_allowed":true}}`))
	request.Header.Set("Authorization", "Bearer publisher-token")
	response := httptest.NewRecorder()
	h.GetReviewerFeedbackThread(response, request, "svc_other", "srun_other", thread.ID)
	if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "Save does nothing") {
		t.Fatalf("different public URL read feedback: %d %s", response.Code, response.Body.String())
	}
}
