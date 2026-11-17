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

type feedbackStoreStub struct {
	FeedbackStore
	service, preview, operation, actor string
	err                                error
}

func (s *feedbackStoreStub) AuthorizeImplementerFeedback(_ context.Context, actor, service, preview, operation string, _ time.Time) (controlv1.FeedbackAuthorization, error) {
	s.service, s.preview, s.operation, s.actor = service, preview, operation, actor
	return controlv1.FeedbackAuthorization{ServiceId: service, PreviewId: preview, Operation: controlv1.FeedbackOperation(operation)}, s.err
}
func (s *feedbackStoreStub) AuthorizeReviewerFeedback(_ context.Context, auth controlstate.ServiceHTTPRun, preview, operation string, _ controlstate.FeedbackActor, _ time.Time) (controlv1.FeedbackAuthorization, error) {
	if auth.Subject.ID != s.service {
		return controlv1.FeedbackAuthorization{}, controlstate.ErrFeedbackAccess
	}
	return controlv1.FeedbackAuthorization{ServiceId: s.service, PreviewId: preview, Operation: controlv1.FeedbackOperation(operation)}, s.err
}
func TestFeedbackInputsExcludeOutputOnlyAndReviewerUpdateEvents(t *testing.T) {
	h := &handler{}
	for _, operation := range []string{"thread.created", "update", "delete"} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"run_number":"1","preview_id":"pv_example","operation":"`+operation+`","access":{}}`))
		h.AuthorizeReviewerFeedback(response, request, "svc_example", "srun_example")
		if response.Code != 400 {
			t.Fatal("reviewer accepted an invalid operation", operation, response.Code)
		}
	}
}
func TestFeedbackReportCannotSupplyAnUnverifiedAuthor(t *testing.T) {
	h := &handler{}
	for _, content := range []string{`"report":{"text":"private"}`, `"display_name":"forged author"`, `"evidence":{"html":"private"}`, `"source_at_report":{}`} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"run_number":"1","preview_id":"pv_example","operation":"report","access":{},`+content+`}`))
		h.AuthorizeReviewerFeedback(response, request, "svc_example", "srun_example")
		if response.Code != 400 {
			t.Fatal("control accepted feedback content or an author choice", response.Code)
		}
	}
}
func TestFeedbackOwnerReadsOnlyManageableServiceThreads(t *testing.T) {
	store := &feedbackStoreStub{}
	h := &handler{feedback: store, authorizer: &recordingAuthorizer{principal: testControlReadPrincipal()}}
	request := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/v1/feedback/authorization", strings.NewReader(`{"preview_id":"pv_example","service_id":"svc_example","operation":"read"}`))
		r.Header.Set("Authorization", "Bearer access-token")
		return r
	}
	response := httptest.NewRecorder()
	h.AuthorizeImplementerFeedback(response, request())
	if response.Code != 200 || store.service != "svc_example" || store.preview != "pv_example" || store.actor != "identity_1" || strings.Contains(response.Body.String(), "report") {
		t.Fatal("owner decision lost its checked scope", response.Code, response.Body.String())
	}
	store.err = controlstate.ErrFeedbackAccess
	denied := httptest.NewRecorder()
	h.AuthorizeImplementerFeedback(denied, request())
	if denied.Code != 403 || strings.Contains(denied.Body.String(), "svc_example") {
		t.Fatal("unrelated owner obtained identifiers", denied.Code)
	}
}
func TestReviewerFeedbackReadCannotCrossService(t *testing.T) {
	store := &feedbackStoreStub{service: "svc_actual"}
	h := &handler{feedback: store, dependencies: Stores{ServiceHTTP: &serviceBrowserHandoffStore{}}}
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"run_number":"1","preview_id":"pv_example","operation":"read","access":{"visit_allowed":true}}`))
	r.Header.Set("Authorization", "Bearer publisher-token")
	w := httptest.NewRecorder()
	h.AuthorizeReviewerFeedback(w, r, "svc_other", "srun_other")
	if w.Code != 403 || strings.Contains(w.Body.String(), "svc_actual") {
		t.Fatal("decision crossed its service", w.Code, w.Body.String())
	}
}
