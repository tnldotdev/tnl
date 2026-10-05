package publisher

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/feedbacktoolbar"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type feedbackControlStub struct{}

func (*feedbackControlStub) AppendFeedbackEvent(context.Context, string, string, controlv1.AppendFeedbackEventRequest) (controlv1.FeedbackEvent, error) {
	return controlv1.FeedbackEvent{Cursor: 1}, nil
}

func (*feedbackControlStub) CreateFeedbackReport(context.Context, string, string, controlv1.CreateFeedbackReportRequest, credentials.PublishRunToken) (controlv1.FeedbackThread, error) {
	return controlv1.FeedbackThread{}, nil
}

func (*feedbackControlStub) ListPreviewPageFeedback(context.Context, string, controlv1.PreviewPageFeedbackRequest, credentials.PublishRunToken) (controlv1.FeedbackThreadPage, error) {
	return controlv1.FeedbackThreadPage{Threads: []controlv1.FeedbackThreadSummary{}, EventCursor: 0}, nil
}

func (*feedbackControlStub) GetReviewerFeedbackThread(context.Context, string, string, controlv1.ReviewerFeedbackReadRequest, credentials.PublishRunToken) (controlv1.FeedbackThread, error) {
	return controlv1.FeedbackThread{}, nil
}

func (*feedbackControlStub) ListReviewerFeedbackEvents(context.Context, string, string, controlv1.ReviewerFeedbackReadRequest, credentials.PublishRunToken) (controlv1.FeedbackEventPage, error) {
	return controlv1.FeedbackEventPage{Events: []controlv1.FeedbackEvent{}}, nil
}

func (*feedbackControlStub) AppendReviewerFeedbackEvent(context.Context, string, string, string, controlv1.AppendReviewerFeedbackEventRequest, credentials.PublishRunToken) (controlv1.FeedbackEvent, error) {
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

func TestFeedbackOwnerHandoffKeepsDeveloperControlsOffReviewerRequests(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	asset, assetPath := feedbacktoolbar.Script()
	owner := NewOwnerHandoff()
	runtime := &feedbackRuntime{
		client: &feedbackControlStub{}, previewID: "pv_0123456789abcdefghijkl",
		runID: "pr_run", service: "web", projectRoot: t.TempDir(), hostname: "route.example",
		browsers: make(map[[32]byte]*browserTrail), asset: asset, assetPath: assetPath, owner: owner,
	}
	route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", Target: upstream.URL, Feedback: runtime})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	serve := func(method, path, cookies, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Host, request.TLS = "route.example", &tls.ConnectionState{ServerName: "route.example"}
		request.Header.Set("Idempotency-Key", "owner-test")
		if cookies != "" {
			request.Header.Set("Cookie", cookies)
		}
		response := httptest.NewRecorder()
		route.http.Handler.ServeHTTP(response, request)
		return response
	}
	if status := serve(http.MethodGet, "/__tnl/feedback/owner", "", ""); !strings.Contains(status.Body.String(), `"owner":false`) {
		t.Fatalf("reviewer was given owner controls: %s", status.Body.String())
	}
	threadID := "fb_0123456789abcdefghijkl"
	readyPath := "/__tnl/feedback/" + threadID + "/events"
	if result := serve(http.MethodPost, readyPath, "", `{"type":"fix.ready_for_recheck","text":"fixed"}`); result.Code != http.StatusForbidden {
		t.Fatalf("reviewer marked feedback ready: %d", result.Code)
	}
	link, err := owner.NewLink("https://route.example")
	if err != nil {
		t.Fatal(err)
	}
	redirect := serve(http.MethodGet, strings.TrimPrefix(link, "https://route.example"), "", "")
	if redirect.Code != http.StatusSeeOther || redirect.Header().Get("Location") != "https://route.example/#tnl-feedback" || len(redirect.Result().Cookies()) != 1 {
		t.Fatalf("owner handoff = %d %#v", redirect.Code, redirect.Header())
	}
	cookie := redirect.Result().Cookies()[0]
	if !cookie.Secure || !cookie.HttpOnly || cookie.Domain != "" || cookie.Name != feedbackOwnerCookieName {
		t.Fatalf("owner cookie is not host-only: %+v", cookie)
	}
	ownerCookie := cookie.Name + "=" + cookie.Value
	if status := serve(http.MethodGet, "/__tnl/feedback/owner", ownerCookie, ""); !strings.Contains(status.Body.String(), `"owner":true`) {
		t.Fatalf("redeemed owner cannot see controls: %s", status.Body.String())
	}
	if ready := serve(http.MethodPost, readyPath, ownerCookie, `{"type":"fix.ready_for_recheck","text":"fixed"}`); ready.Code != http.StatusOK {
		t.Fatalf("developer could not mark feedback ready: %d %s", ready.Code, ready.Body.String())
	}
}
