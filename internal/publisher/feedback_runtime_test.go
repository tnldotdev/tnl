package publisher

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/feedbacktoolbar"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/api/publisherv1"
)

type feedbackControlStub struct {
	event  controlv1.AppendReviewerFeedbackEventRequest
	page   controlv1.PreviewPageFeedbackRequest
	thread controlv1.FeedbackThread
	create controlv1.CreateFeedbackReportRequest
}

func (s *feedbackControlStub) CreateFeedbackReport(_ context.Context, _, _ string, input controlv1.CreateFeedbackReportRequest, _ credentials.PublishRunToken) (controlv1.FeedbackThread, error) {
	s.create = input
	return s.thread, nil
}

func (s *feedbackControlStub) ListPreviewPageFeedback(_ context.Context, _ string, body controlv1.PreviewPageFeedbackRequest, _ credentials.PublishRunToken) (controlv1.FeedbackThreadPage, error) {
	s.page = body
	return controlv1.FeedbackThreadPage{Threads: []controlv1.FeedbackThreadSummary{}, EventCursor: 0}, nil
}

func (s *feedbackControlStub) GetReviewerFeedbackThread(context.Context, string, string, controlv1.ReviewerFeedbackReadRequest, credentials.PublishRunToken) (controlv1.FeedbackThread, error) {
	return s.thread, nil
}

func (*feedbackControlStub) ListReviewerFeedbackEvents(context.Context, string, string, controlv1.ReviewerFeedbackReadRequest, credentials.PublishRunToken) (controlv1.FeedbackEventPage, error) {
	return controlv1.FeedbackEventPage{Events: []controlv1.FeedbackEvent{}}, nil
}

func (s *feedbackControlStub) AppendReviewerFeedbackEvent(_ context.Context, _, _, _ string, body controlv1.AppendReviewerFeedbackEventRequest, _ credentials.PublishRunToken) (controlv1.FeedbackEvent, error) {
	s.event = body
	return controlv1.FeedbackEvent{}, nil
}

func TestFeedbackHTMLInjectionAndPerBrowserFailuresKeepAppCookies(t *testing.T) {
	appCookies := make(chan string, 2)
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		appCookies <- request.Header.Get("Cookie")
		if request.URL.Path == "/fail" {
			http.Error(response, "bad request", http.StatusInternalServerError)
			return
		}
		response.Header().Set("Content-Type", "text/html; charset=utf-8")
		response.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'none'")
		response.Header().Set("ETag", "app-etag")
		_, _ = response.Write([]byte("<!doctype html><html><head></head><body>app</body></html>"))
	}))
	defer upstream.Close()
	asset, assetPath := feedbacktoolbar.Script()
	runtime := &feedbackRuntime{
		client: &feedbackControlStub{}, previewID: "pv_0123456789abcdefghijkl", service: "web",
		browsers: make(map[[32]byte]*browserTrail), asset: asset, assetPath: assetPath,
	}
	route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", Target: upstream.URL, Feedback: runtime})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	serve := func(path, cookies string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Host = "route.example"
		request.TLS = &tls.ConnectionState{ServerName: "route.example"}
		if cookies != "" {
			request.Header.Set("Cookie", cookies)
		}
		response := httptest.NewRecorder()
		route.http.Handler.ServeHTTP(response, request)
		return response
	}
	page := serve("/", "app_session=ok")
	if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), assetPath) ||
		!strings.Contains(page.Header().Get("Content-Security-Policy"), "'nonce-") ||
		page.Header().Get("ETag") != "" || len(page.Result().Cookies()) != 1 {
		t.Fatalf("feedback HTML response = %d, %q, %#v", page.Code, page.Body.String(), page.Header())
	}
	if got := <-appCookies; got != "app_session=ok" {
		t.Fatalf("initial app cookie = %q", got)
	}
	browserCookie := page.Result().Cookies()[0]
	visitorCookies := "app_session=ok; " + browserCookie.Name + "=" + browserCookie.Value
	failed := serve("/fail?token=private", visitorCookies)
	if failed.Code != http.StatusInternalServerError {
		t.Fatalf("upstream failure = %d", failed.Code)
	}
	if got := <-appCookies; got != "app_session=ok" {
		t.Fatalf("tnl browser cookie reached local service: %q", got)
	}
	evidence := serve("/__tnl/feedback/evidence", visitorCookies)
	if evidence.Code != http.StatusOK || strings.Contains(evidence.Body.String(), "private") {
		t.Fatalf("failed request included query secret: %d %s", evidence.Code, evidence.Body.String())
	}
	var result struct {
		FailedRequests []failedRequest `json:"failed_requests"`
	}
	if err := json.Unmarshal(evidence.Body.Bytes(), &result); err != nil || len(result.FailedRequests) != 1 ||
		result.FailedRequests[0].Method != "GET" || result.FailedRequests[0].Path != "/fail" || result.FailedRequests[0].Status != 500 {
		t.Fatalf("per-browser failed request = %+v, %v", result, err)
	}
	toolbar := serve(assetPath, visitorCookies)
	if toolbar.Code != http.StatusOK || toolbar.Header().Get("Content-Type") != "text/javascript; charset=utf-8" ||
		!strings.Contains(toolbar.Header().Get("Cache-Control"), "immutable") || len(toolbar.Body.Bytes()) != len(asset) {
		t.Fatalf("versioned toolbar asset = %d %#v", toolbar.Code, toolbar.Header())
	}
}

func TestFeedbackResolveAndReopenUsePreviewAccess(t *testing.T) {
	client := &feedbackControlStub{}
	runtime := &feedbackRuntime{client: client, runID: "pr_run", version: 2}
	for _, kind := range []string{"thread.resolved", "thread.reopened"} {
		for _, allowedIP := range []bool{true, false} {
			request := httptest.NewRequest(http.MethodPost, "/__tnl/feedback/fb_0123456789abcdefghijkl/events", strings.NewReader(`{"schema_version":1,"type":"`+kind+`"}`))
			request.Header.Set("Idempotency-Key", kind)
			if !allowedIP {
				request.AddCookie(&http.Cookie{Name: shareCookieName, Value: "shr_0123456789abcdefghijkl.secret"})
			}
			response := httptest.NewRecorder()
			runtime.handle(response, request, !allowedIP)
			if response.Code != http.StatusOK || string(client.event.Type) != kind || client.event.Access.AllowedIp != allowedIP || client.event.SourceState != nil {
				t.Fatalf("%s through preview access = %d, %+v", kind, response.Code, client.event)
			}
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/__tnl/feedback/fb_0123456789abcdefghijkl/events", strings.NewReader(`{"type":"thread.resolved"}`))
	response := httptest.NewRecorder()
	runtime.handle(response, request, true)
	if response.Code != http.StatusForbidden {
		t.Fatalf("missing preview access accepted: %d", response.Code)
	}
}

func TestFeedbackListFiltersKeepPublisherScope(t *testing.T) {
	for _, path := range []string{"/__tnl/feedback?state=resolved", "/__tnl/feedback?state=resolved&path=%2Fsettings"} {
		client := &feedbackControlStub{}
		runtime := &feedbackRuntime{client: client, runID: "pr_run", version: 2, previewID: "pv_0123456789abcdefghijkl"}
		request := httptest.NewRequest(http.MethodGet, path+"&preview_id=other&public_url_id=other", nil)
		response := httptest.NewRecorder()
		runtime.handle(response, request, false)
		if response.Code != http.StatusOK || client.page.PreviewId != runtime.previewID || client.page.PublishRunNumber != 2 || !client.page.Access.AllowedIp || client.page.State == nil || *client.page.State != controlv1.Resolved {
			t.Fatalf("feedback list escaped publisher scope: %d, %+v", response.Code, client.page)
		}
		if strings.Contains(path, "path=") {
			if client.page.PagePath == nil || *client.page.PagePath != "/settings" {
				t.Fatalf("page filter = %v", client.page.PagePath)
			}
		} else if client.page.PagePath != nil {
			t.Fatalf("all-pages filter = %v", client.page.PagePath)
		}
	}
}

func TestFeedbackPublisherContractKeepsSourceAndScopeOutOfBrowserInput(t *testing.T) {
	load := func(name string, value any) {
		t.Helper()
		contents, err := os.ReadFile("../../api/fixtures/publisher/v1/" + name + ".json")
		if err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(strings.NewReader(string(contents)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(value); err != nil {
			t.Fatal(err)
		}
	}
	var thread controlv1.FeedbackThread
	var input publisherv1.BrowserFeedbackReportRequest
	load("thread", &thread)
	load("report-request", &input)
	control := &feedbackControlStub{thread: thread}
	runtime := &feedbackRuntime{client: control, previewID: thread.Scope.PreviewId, service: "web", runID: thread.Scope.PublishRunId, version: 2, demo: true}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		runtime.handle(response, request, false)
	}))
	defer server.Close()
	client, err := publisherv1.NewClientWithResponses(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	created, err := client.CreateBrowserFeedbackReportWithResponse(t.Context(), &publisherv1.CreateBrowserFeedbackReportParams{IdempotencyKey: "fixture-report"}, input)
	if err != nil || created.JSON200 == nil || created.JSON200.Id != thread.Id || created.JSON200.Report.Text != input.Text {
		t.Fatalf("browser report contract failed: %v", err)
	}
	if control.create.PreviewId != runtime.previewID || control.create.PublishRunNumber != 2 || control.create.Service != "web" || !control.create.Access.AllowedIp ||
		control.create.SourceAtReport.Complete || control.create.SourceAtReport.HeadCommit != "" || len(control.create.SourceAtReport.ChangedFiles) != 0 {
		t.Fatalf("publisher did not provide report scope and demo source state: %+v", control.create)
	}
	read, err := client.GetBrowserFeedbackThreadWithResponse(t.Context(), thread.Id)
	if err != nil || read.JSON200 == nil || read.JSON200.Scope.PreviewId != thread.Scope.PreviewId || read.JSON200.Scope.Service != "web" || read.JSON200.SourceAtReport.SchemaVersion != 1 || read.JSON200.SourceAtReport.Complete {
		t.Fatalf("browser thread contract failed: %v", err)
	}
	for _, forged := range []string{
		`{"schema_version":1,"text":"forged","page_path":"/","preview_id":"other","evidence":{"schema_version":1,"actions":[],"failed_requests":[]}}`,
		`{"schema_version":1,"text":"forged","page_path":"/","source_at_report":{"complete":true},"evidence":{"schema_version":1,"actions":[],"failed_requests":[]}}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/__tnl/feedback", strings.NewReader(forged))
		request.Header.Set("Idempotency-Key", "forged")
		response := httptest.NewRecorder()
		runtime.handle(response, request, false)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("browser-supplied scope or source state accepted: %d", response.Code)
		}
	}
}
