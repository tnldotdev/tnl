package controlapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
)

type feedbackStoreStub struct {
	FeedbackStore
	thread  controlstate.FeedbackThread
	pageURL string
}

func (s *feedbackStoreStub) GetFeedback(_ context.Context, _ string) (controlstate.FeedbackThread, error) {
	return s.thread, nil
}

func (s *feedbackStoreStub) ReviewerFeedbackScope(_ context.Context, _ controlstate.PublishRunAuthentication, _ string, _ controlstate.FeedbackActor, _ time.Time) (string, string, error) {
	return s.thread.TeamID, s.pageURL, nil
}

func (s *feedbackStoreStub) ListFeedbackForTeam(_ context.Context, _, _ string) (controlstate.FeedbackThreadPage, error) {
	return controlstate.FeedbackThreadPage{Threads: []controlstate.FeedbackThread{s.thread}, EventCursor: 3}, nil
}

type feedbackAuthStoreStub struct {
	PublicURLStore
	auth controlstate.PublishRunAuthentication
}

func (s *feedbackAuthStoreStub) PublishRunAuthentication(_ context.Context, _ string, _ uint64, _ credentials.PublishRunToken) (controlstate.PublishRunAuthentication, error) {
	return s.auth, nil
}

func feedbackTestThread() controlstate.FeedbackThread {
	return controlstate.FeedbackThread{
		ID: "fb_0123456789abcdefghijkl", PreviewID: "pv_0123456789abcdefghijkl",
		TeamID: "team_1", PublicURLID: "url_1", PublishRunID: "pr_1", PublishRunNumber: 2,
		PagePath: "/settings", Service: "web", State: controlstate.FeedbackOpen,
		SchemaVersion: 1, MessageCount: 1, ReportText: "Save does nothing",
		Evidence:       json.RawMessage(`{"schema_version":1,"actions":[],"failed_requests":[]}`),
		SourceAtReport: json.RawMessage(`{"schema_version":1,"head_commit":"","project_path":"","branch":"","changed_files":[],"complete":false}`),
		CreatedAt:      time.Now().UTC(), StateUpdatedAt: time.Now().UTC(),
	}
}

func TestFeedbackOwnerReadsOnlyManageablePublicURLThreads(t *testing.T) {
	thread := feedbackTestThread()
	store := &feedbackStoreStub{thread: thread}
	authorizer := &recordingAuthorizer{principal: testPublicURLReadPrincipal(), decision: authorization.Decision{
		IdentityID: "identity_1", TeamID: "team_1", PolicyRevision: 1,
	}}
	h := &handler{feedback: store, authorizer: authorizer, store: &publicURLMutationStoreStub{route: controlstate.PublicURL{
		ID: thread.PublicURLID, TeamID: thread.TeamID, DomainID: "domain_1", MembershipID: "membership_1",
		CanonicalHostname: "web.example.test", Target: "http://127.0.0.1:3000",
		PublicURLScope: controlstate.PublicURLScopeMember, LifecycleState: controlstate.PublicURLLifecycleEnabled,
		MutationRevision: 4,
	}}}
	request := httptest.NewRequest(http.MethodGet, "/v1/feedback/"+thread.ID, nil)
	request.Header.Set("Authorization", "Bearer access-token")
	response := httptest.NewRecorder()
	h.GetFeedbackThread(response, request, thread.ID)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"text":"Save does nothing"`) || len(authorizer.requests) != 1 ||
		authorizer.requests[0].Operation != authorization.OperationFeedbackManage ||
		authorizer.requests[0].PublicURLID != thread.PublicURLID || authorizer.requests[0].PublicURLMutationRevision != 4 {
		t.Fatalf("feedback read = %d %s; auth=%+v", response.Code, response.Body.String(), authorizer.requests)
	}
	authorizer.principal.teamIDs = map[string]struct{}{"team_other": {}}
	denied := httptest.NewRecorder()
	h.GetFeedbackThread(denied, request, thread.ID)
	if denied.Code != http.StatusNotFound || strings.Contains(denied.Body.String(), "Save does nothing") {
		t.Fatalf("unrelated team read private feedback: %d %s", denied.Code, denied.Body.String())
	}
}

func TestReviewerFeedbackReadCannotCrossPublicURL(t *testing.T) {
	thread := feedbackTestThread()
	store := &feedbackStoreStub{thread: thread, pageURL: thread.PublicURLID}
	h := &handler{feedback: store, store: &feedbackAuthStoreStub{auth: controlstate.PublishRunAuthentication{
		PublishRunID: "pr_other", PublicURLID: "url_other", PublishRunNumber: 1,
	}}}
	request := httptest.NewRequest(http.MethodPost, "/v1/publish-runs/pr_other/feedback/"+thread.ID+"/query",
		strings.NewReader(`{"publish_run_number":1,"preview_id":"pv_0123456789abcdefghijkl","access":{"allowed_ip":true}}`))
	request.Header.Set("Authorization", "Bearer publisher-token")
	response := httptest.NewRecorder()
	h.GetReviewerFeedbackThread(response, request, "pr_other", thread.ID)
	if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), "Save does nothing") {
		t.Fatalf("different public URL read feedback: %d %s", response.Code, response.Body.String())
	}
}
