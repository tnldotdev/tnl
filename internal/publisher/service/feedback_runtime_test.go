//go:build !js || !wasm

package service

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/publisher/toolbar"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	publisherv1 "github.com/tnldotdev/tnl/pkg/api/publisher/browser/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type feedbackControlStub struct {
	HTTPControl
	serviceID, runID string
	token            credentials.ServiceRunToken
	event            controlv1.AppendReviewerFeedbackEventRequest
	page             controlv1.PreviewPageFeedbackRequest
	read             controlv1.ReviewerFeedbackReadRequest
	preview          func(context.Context, string, string, int64, credentials.ServiceRunToken) (controlv1.Preview, error)
	err              error
	authorization    controlv1.AuthorizeReviewerFeedbackRequest
}

func testFeedbackState(t *testing.T) *clientstate.Store {
	t.Helper()
	d, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	profile, err := d.Server(t.Context(), "https://control.example.test")
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func testFeedbackDecision(service, run string, body controlv1.AuthorizeReviewerFeedbackRequest) controlv1.FeedbackAuthorization {
	return controlv1.FeedbackAuthorization{PreviewId: body.PreviewId, ServiceId: service, ServiceRunId: run, RunNumber: body.RunNumber, Operation: body.Operation, Actor: "reviewer",
		Author: controlv1.FeedbackAuthor{IdentityId: new("ident_0123456789abcdefghijkl"), DisplayName: "Verified reviewer", Verified: true}, ExpiresAt: time.Now().Add(4 * time.Second), ContentExpiresAt: new(time.Now().Add(time.Hour))}
}

func (s *feedbackControlStub) AuthorizeReviewerFeedback(_ context.Context, service, run string, body controlv1.AuthorizeReviewerFeedbackRequest, token credentials.ServiceRunToken) (controlv1.FeedbackAuthorization, error) {
	s.bind(service, run, token)
	s.authorization = body
	s.page = controlv1.PreviewPageFeedbackRequest{PreviewId: body.PreviewId, RunNumber: body.RunNumber, Access: body.Access}
	s.read = controlv1.ReviewerFeedbackReadRequest{PreviewId: body.PreviewId, RunNumber: body.RunNumber, Access: body.Access}
	s.event = controlv1.AppendReviewerFeedbackEventRequest{RunNumber: body.RunNumber, Access: body.Access, Type: controlv1.ReviewerFeedbackEventInputType(body.Operation)}
	return testFeedbackDecision(service, run, body), s.err
}

func (s *feedbackControlStub) CreateServiceRunPreview(ctx context.Context, service, run string, number int64, token credentials.ServiceRunToken) (controlv1.Preview, error) {
	return s.preview(ctx, service, run, number, token)
}

func (s *feedbackControlStub) bind(service, run string, token credentials.ServiceRunToken) {
	s.serviceID, s.runID, s.token = service, run, token
}

func testFeedbackRuntime(t *testing.T, f *HTTP, control *feedbackControlStub) *feedbackRuntime {
	t.Helper()
	f.Control = serviceHTTPControl{HTTPControl: control}
	f.State = testFeedbackState(t)
	f.Feedback, f.PreviewID, f.ProjectService, f.Demo = true, "pv_0123456789abcdefghijkl", "web", true
	runtime, err := newFeedbackRuntime(*f)
	if err != nil {
		t.Fatal(err)
	}
	f.feedback, f.ResponseHooks = runtime, runtime.responseHooks(f.ResponseHooks)
	return runtime
}

func feedbackVisit(t *testing.T, client *http.Client, method, path, cookies string) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), method, "https://preview.example.test"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Cookie", cookies)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return response, body
}

func TestFeedbackHTMLInjectionAndPerBrowserFailuresKeepAppCookies(t *testing.T) {
	appCookies := make(chan string, 2)
	control := &feedbackControlStub{}
	var runtime *feedbackRuntime
	client, _, _, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		appCookies <- request.Header.Get("Cookie")
		if request.URL.Path == "/fail" {
			http.Error(response, "bad request", http.StatusInternalServerError)
			return
		}
		response.Header().Set("Content-Type", "text/html; charset=utf-8")
		response.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'none'")
		response.Header().Set("ETag", "app-etag")
		_, _ = io.WriteString(response, "<!doctype html><html><head></head><body>app</body></html>")
	}), false, false, func(f *HTTP) { runtime = testFeedbackRuntime(t, f, control) })
	cookies := "app_session=ok; " + httpaccess.VisitorTokenCookie + "=" + token.Reveal()
	page, body := feedbackVisit(t, client, http.MethodGet, "/", cookies)
	if page.StatusCode != http.StatusOK || !strings.Contains(string(body), runtime.assetPath) ||
		!strings.Contains(page.Header.Get("Content-Security-Policy"), "'nonce-") ||
		page.Header.Get("ETag") != "" || len(page.Cookies()) != 1 {
		t.Fatal("feedback HTML response changed", page.StatusCode, string(body), page.Header)
	}
	if got := <-appCookies; got != "app_session=ok" {
		t.Fatalf("initial app cookie = %q", got)
	}
	browserCookie := page.Cookies()[0]
	if browserCookie.Name != httpaccess.FeedbackBrowserCookieName || !browserCookie.Secure || !browserCookie.HttpOnly || browserCookie.Domain != "" {
		t.Fatal("feedback tracking cookie escaped its host")
	}
	cookies += "; " + browserCookie.Name + "=" + browserCookie.Value
	failed, _ := feedbackVisit(t, client, http.MethodGet, "/fail?token=private", cookies)
	if failed.StatusCode != http.StatusInternalServerError {
		t.Fatal("upstream failure changed", failed.StatusCode)
	}
	if got := <-appCookies; got != "app_session=ok" {
		t.Fatalf("tnl browser cookie reached local service: %q", got)
	}
	evidence, body := feedbackVisit(t, client, http.MethodGet, "/__tnl/feedback/evidence", cookies)
	var result publisherv1.BrowserFeedbackEvidence
	if evidence.StatusCode != http.StatusOK || strings.Contains(string(body), "private") ||
		json.Unmarshal(body, &result) != nil || len(result.FailedRequests) != 1 ||
		result.FailedRequests[0].Method != "GET" || result.FailedRequests[0].Path != "/fail" || result.FailedRequests[0].Status != 500 {
		t.Fatal("per-browser failed request leaked a secret or changed", evidence.StatusCode, string(body))
	}
	_, other := feedbackVisit(t, client, http.MethodGet, "/__tnl/feedback/evidence", httpaccess.VisitorTokenCookie+"="+token.Reveal())
	if strings.Contains(string(other), "/fail") {
		t.Fatal("another browser received the failure trail")
	}
	asset, body := feedbackVisit(t, client, http.MethodGet, runtime.assetPath, cookies)
	if asset.StatusCode != http.StatusOK || asset.Header.Get("Content-Type") != "text/javascript; charset=utf-8" ||
		!strings.Contains(asset.Header.Get("Cache-Control"), "immutable") || len(body) != len(runtime.asset) {
		t.Fatal("versioned toolbar asset changed", asset.StatusCode, asset.Header)
	}
}

func TestFeedbackResolveAndReopenUsePreviewAccess(t *testing.T) {
	client := &feedbackControlStub{}
	runtime := &feedbackRuntime{client: client, state: testFeedbackState(t), demo: true, previewID: "pv_0123456789abcdefghijkl", service: "web", serviceID: "svc_0123456789abcdefghijkl", runID: "srun_0123456789abcdefghijkl", number: 2, token: "run-token"}
	for _, kind := range []string{"thread.resolved", "thread.reopened"} {
		for _, allowed := range []bool{true, false} {
			local, err := runtime.local(t.Context(), controlv1.FeedbackReviewerAccess{VisitAllowed: allowed})
			if err != nil {
				t.Fatal(err)
			}
			body := controlv1.CreateFeedbackReportRequest{PreviewId: runtime.previewID, Service: "web", PagePath: "/", RunNumber: runtime.number}
			body.Report.Text = "A suggestion"
			body.SourceAtReport = controlv1.SourceState{SchemaVersion: 1, ChangedFiles: []controlv1.SourceFileState{}}
			body.Evidence = controlv1.FeedbackEvidence{SchemaVersion: 1}
			thread, err := local.Create(t.Context(), runtime.serviceID, runtime.runID, kind+strconv.FormatBool(allowed), body)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "thread.reopened" {
				if _, err := local.AppendFeedbackEvent(t.Context(), thread.Id, "prepare", controlv1.AppendFeedbackEventRequest{Type: "thread.resolved"}); err != nil {
					t.Fatal(err)
				}
			}
			request := httptest.NewRequest(http.MethodPost, "/__tnl/feedback/"+thread.Id+"/events", strings.NewReader(`{"schema_version":1,"type":"`+kind+`"}`))
			request.Header.Set("Idempotency-Key", kind)
			if !allowed {
				request.AddCookie(&http.Cookie{Name: httpaccess.ShareCookieName, Value: "shr_0123456789abcdefghijkl." + visitorfixture.BrowserCookie})
			}
			response := httptest.NewRecorder()
			runtime.handle(response, request, feedbackAuthorization{allowed: allowed})
			if response.Code != http.StatusOK || string(client.event.Type) != kind || client.event.Access.VisitAllowed != allowed ||
				client.event.SourceState != nil || client.event.RunNumber != runtime.number || client.serviceID != runtime.serviceID ||
				client.runID != runtime.runID || client.token != runtime.token {
				t.Fatal("feedback event escaped the service run", kind, response.Code, client.event)
			}
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/__tnl/feedback/fb_0123456789abcdefghijkl/events", strings.NewReader(`{"type":"thread.resolved"}`))
	response := httptest.NewRecorder()
	runtime.handle(response, request, feedbackAuthorization{})
	if response.Code != http.StatusForbidden {
		t.Fatal("missing preview access was accepted", response.Code)
	}
}

func TestFeedbackReportDoesNotAddUnselectedBrowserActivity(t *testing.T) {
	control := &feedbackControlStub{}
	runtime := &feedbackRuntime{client: control, state: testFeedbackState(t), previewID: "pv_0123456789abcdefghijkl", service: "web",
		serviceID: "svc_0123456789abcdefghijkl", runID: "srun_0123456789abcdefghijkl", number: 2,
		token: "run-token", demo: true, browsers: make(map[[32]byte]*browserTrail)}
	cookie := &http.Cookie{Name: httpaccess.FeedbackBrowserCookieName, Value: visitorfixture.BrowserCookie}
	failed := httptest.NewRequest(http.MethodGet, "https://preview.example.test/fail?token=private", nil)
	failed.AddCookie(cookie)
	failed = runtime.prepareBrowser(httptest.NewRecorder(), failed)
	runtime.observe(failed, http.StatusInternalServerError)
	if len(runtime.evidenceForBrowser(failed)) != 1 {
		t.Fatal("fixture did not capture a browser-local failure")
	}
	request := httptest.NewRequest(http.MethodPost, "/__tnl/feedback", strings.NewReader(
		`{"schema_version":1,"text":"Only the reviewed report","page_path":"/","evidence":{"schema_version":1,"actions":[],"failed_requests":[]}}`))
	request.AddCookie(cookie)
	request.Header.Set("Idempotency-Key", "omit-activity")
	response := httptest.NewRecorder()
	runtime.handle(response, request, feedbackAuthorization{allowed: true})
	var thread controlv1.FeedbackThread
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &thread) != nil ||
		thread.Report.Text != "Only the reviewed report" || thread.Evidence.SchemaVersion != 1 ||
		len(thread.Evidence.Actions) != 0 || len(thread.Evidence.FailedRequests) != 0 || thread.Evidence.Element != nil {
		t.Fatal("publisher added unselected activity to the report", response.Code, response.Body.String())
	}
}

func TestFeedbackListFiltersKeepPublisherScope(t *testing.T) {
	for _, path := range []string{"/__tnl/feedback?state=resolved", "/__tnl/feedback?state=resolved&path=%2Fsettings"} {
		client := &feedbackControlStub{}
		runtime := &feedbackRuntime{client: client, state: testFeedbackState(t), demo: true, serviceID: "svc_0123456789abcdefghijkl", runID: "srun_0123456789abcdefghijkl", number: 2, token: "run-token", previewID: "pv_0123456789abcdefghijkl"}
		request := httptest.NewRequest(http.MethodGet, path+"&preview_id=other&service_id=other&service_run_id=other&run_number=99", nil)
		response := httptest.NewRecorder()
		runtime.handle(response, request, feedbackAuthorization{allowed: true})
		if response.Code != http.StatusOK || client.page.PreviewId != runtime.previewID || client.page.RunNumber != 2 ||
			!client.page.Access.VisitAllowed || client.page.State != nil ||
			client.serviceID != runtime.serviceID || client.runID != runtime.runID || client.token != runtime.token {
			t.Fatal("feedback list escaped service scope", response.Code, client.page)
		}
		if client.page.PagePath != nil {
			t.Fatal("page filter was sent to control", client.page.PagePath)
		}
	}
}

func TestFeedbackBrowserAuthorComesFromSessionFactNotVisitorToken(t *testing.T) {
	control := &feedbackControlStub{}
	client, _, _, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("feedback reached the application")
	}), false, true, func(f *HTTP) { testFeedbackRuntime(t, f, control) })
	for _, cookie := range []string{"", httpaccess.BrowserCookieName + "=" + visitorfixture.BrowserCookie,
		httpaccess.BrowserCookieName + "=invalid", httpaccess.BrowserCookieName + "=" + visitorfixture.BrowserCookie + "; " + httpaccess.BrowserCookieName + "=" + visitorfixture.BrowserCookie,
		httpaccess.ShareCookieName + "=shr_0123456789abcdefghijkl.invalid",
		httpaccess.ShareCookieName + "=shr_0123456789abcdefghijkl." + visitorfixture.BrowserCookie + "; " + httpaccess.ShareCookieName + "=shr_0123456789abcdefghijkl." + visitorfixture.BrowserCookie} {
		control.page = controlv1.PreviewPageFeedbackRequest{}
		cookies := httpaccess.VisitorTokenCookie + "=" + token.Reveal()
		if cookie != "" {
			cookies += "; " + cookie
		}
		response, _ := feedbackVisit(t, client, http.MethodGet, "/__tnl/feedback", cookies)
		if cookie == "" {
			if response.StatusCode != http.StatusOK || control.page.Access.BrowserCookieSecret != nil {
				t.Fatal("visitor permission supplied verified author facts")
			}
		} else if cookie == httpaccess.BrowserCookieName+"="+visitorfixture.BrowserCookie {
			if response.StatusCode != http.StatusOK || control.page.Access.BrowserCookieSecret == nil || *control.page.Access.BrowserCookieSecret != visitorfixture.BrowserCookie {
				t.Fatal("feedback lost its factual browser sign-in")
			}
		} else if response.StatusCode != http.StatusForbidden || control.page.PreviewId != "" {
			t.Fatal("invalid browser/share proof fell back to anonymous feedback", cookie, response.StatusCode)
		}
		if cookie != "" && cookie != httpaccess.BrowserCookieName+"="+visitorfixture.BrowserCookie {
			_, assetPath := toolbar.Script()
			for _, path := range []string{"/__tnl/feedback/evidence", assetPath} {
				response, _ := feedbackVisit(t, client, http.MethodGet, path, cookies)
				if response.StatusCode != http.StatusForbidden {
					t.Fatal("malformed browser/share proof reached a reserved feedback resource", path, response.StatusCode)
				}
			}
		}
	}
}

func TestFeedbackPublisherContractKeepsSourceAndScopeOutOfBrowserInput(t *testing.T) {
	load := func(name string, value any) {
		t.Helper()
		contents, err := os.ReadFile("../../../contracts/fixtures/publisher/v1/" + name + ".json")
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
	control := &feedbackControlStub{}
	runtime := &feedbackRuntime{client: control, previewID: thread.Scope.PreviewId, service: "web", serviceID: thread.Scope.ServiceId,
		runID: thread.Scope.ServiceRunId, number: 2, token: "run-token", demo: true, state: testFeedbackState(t)}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		runtime.handle(response, request, feedbackAuthorization{allowed: true})
	}))
	defer server.Close()
	client, err := publisherv1.NewClientWithResponses(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	created, err := client.CreateBrowserFeedbackReportWithResponse(t.Context(), &publisherv1.CreateBrowserFeedbackReportParams{IdempotencyKey: "fixture-report"}, input)
	if err != nil || created.JSON200 == nil || created.JSON200.Report.Text != input.Text {
		t.Fatal("browser report contract failed", err)
	}
	if control.authorization.PreviewId != runtime.previewID || control.authorization.RunNumber != 2 || !control.authorization.Access.VisitAllowed ||
		created.JSON200.SourceAtReport.Complete || created.JSON200.SourceAtReport.HeadCommit != "" || len(created.JSON200.SourceAtReport.ChangedFiles) != 0 ||
		control.serviceID != runtime.serviceID || control.runID != runtime.runID || control.token != runtime.token {
		t.Fatal("service did not retain report scope and incomplete demo source locally")
	}
	read, err := client.GetBrowserFeedbackThreadWithResponse(t.Context(), created.JSON200.Id)
	if err != nil || read.JSON200 == nil || read.JSON200.Scope.PreviewId != thread.Scope.PreviewId ||
		read.JSON200.Scope.ServiceId != thread.Scope.ServiceId || read.JSON200.Scope.ServiceRunId != runtime.runID ||
		read.JSON200.Scope.RunNumber != 2 || read.JSON200.Scope.Service != "web" || read.JSON200.SourceAtReport.SchemaVersion != 1 || read.JSON200.SourceAtReport.Complete {
		t.Fatal("browser thread contract failed", err)
	}
	if control.read.RunNumber != 2 || control.read.PreviewId != runtime.previewID {
		t.Fatal("thread read lost the current service run")
	}
	if events, err := client.ListBrowserFeedbackEventsWithResponse(t.Context(), created.JSON200.Id, &publisherv1.ListBrowserFeedbackEventsParams{AfterCursor: new(int64(4))}); err != nil ||
		control.read.RunNumber != 2 || control.read.AfterCursor != nil || events.JSON200 == nil || len(events.JSON200.Events) != 0 {
		t.Fatal("event cursor was not applied locally or was sent to control", err)
	}
	for _, forged := range []string{
		`{"schema_version":1,"text":"forged","page_path":"/","display_name":"unverified","evidence":{"schema_version":1,"actions":[],"failed_requests":[]}}`,
		`{"schema_version":1,"text":"forged","page_path":"/","preview_id":"other","evidence":{"schema_version":1,"actions":[],"failed_requests":[]}}`,
		`{"schema_version":1,"text":"forged","page_path":"/","service_id":"other","evidence":{"schema_version":1,"actions":[],"failed_requests":[]}}`,
		`{"schema_version":1,"text":"forged","page_path":"/","service_run_id":"other","run_number":"99","evidence":{"schema_version":1,"actions":[],"failed_requests":[]}}`,
		`{"schema_version":1,"text":"forged","page_path":"/","source_at_report":{"complete":true},"evidence":{"schema_version":1,"actions":[],"failed_requests":[]}}`,
		`{"schema_version":1,"text":"forged","page_path":"/","visit_proof":{"kind":"bearer","token":"forged"},"evidence":{"schema_version":1,"actions":[],"failed_requests":[]}}`,
		`{"schema_version":1,"text":"forged","page_path":"/","access":{"visit_proof":{"kind":"connector","pair_id":"forged","delivery_generation":"1","permission_token":"forged"}},"evidence":{"schema_version":1,"actions":[],"failed_requests":[]}}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/__tnl/feedback", strings.NewReader(forged))
		request.Header.Set("Idempotency-Key", "forged")
		response := httptest.NewRecorder()
		runtime.handle(response, request, feedbackAuthorization{allowed: true})
		if response.Code != http.StatusBadRequest {
			t.Fatal("browser-supplied scope or source state was accepted", response.Code)
		}
	}
}

func TestFeedbackUsesTrustedSourceAndIndependentShareAndBrowserProofs(t *testing.T) {
	control := &feedbackControlStub{}
	var budget *requestlimit.HTTP
	var ingress, apps atomic.Int32
	client, _, update, token := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		apps.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}), false, true, func(f *HTTP) {
		testFeedbackRuntime(t, f, control)
		var err error
		budget, err = requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Total: new(1)})
		if err != nil {
			t.Fatal(err)
		}
		f.Requests = budget
		f.Control = serviceHTTPControl{HTTPControl: control}
		f.ReserveCapacity = func(context.Context) error {
			ingress.Add(1)
			return nil
		}
	})
	shareID := "shr_0123456789abcdefghijkl"
	key := []byte(strings.Repeat("h", 32))
	// this service permission is share-backed; the independent browser session
	// is only an author fact for control, never a replacement visitor identity.
	permission, err := visitortoken.Sign(update.View.Issuer, "http", ed25519.NewKeyFromSeed(key), visitortoken.Permission{
		Scope: update.View.Scope, Hostname: update.View.Hostname, Port: update.View.Port, VisitorPolicyRevision: 1,
		Subject: visitortoken.Share{ShareID: shareID}, ExpiresAt: time.Now().Add(time.Minute)}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test/__tnl/feedback", nil)
	request.Header.Set("X-Forwarded-For", "203.0.113.99")
	request.Header.Set("Forwarded", "for=203.0.113.99")
	request.Header.Set("Cookie", httpaccess.VisitorTokenCookie+"="+permission.Reveal()+"; "+httpaccess.ShareCookieName+"="+shareID+"."+visitorfixture.BrowserCookie+"; "+httpaccess.BrowserCookieName+"="+visitorfixture.BrowserCookie)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	var forwarded controlv1.FeedbackBearerVisitProof
	if response.StatusCode != http.StatusOK || control.page.Access.SourceIp == nil || *control.page.Access.SourceIp != "192.0.2.1" ||
		control.page.Access.VisitProof == nil || control.page.Access.ShareId != nil || control.page.Access.CookieSecret != nil ||
		json.Unmarshal(control.page.Access.VisitProof, &forwarded) != nil || forwarded.Token != permission.Reveal() ||
		control.page.Access.BrowserCookieSecret == nil ||
		*control.page.Access.BrowserCookieSecret != visitorfixture.BrowserCookie {
		t.Fatal("feedback lost its selected share bearer, trusted source, or independent browser author")
	}
	select {
	case <-budget.Completed():
		t.Fatal("reserved feedback spent an application request")
	default:
	}
	if apps.Load() != 0 || ingress.Load() != 0 {
		t.Fatal("feedback reached the target or claimed ingress application quota", apps.Load(), ingress.Load())
	}
	control.err = &clientcontrol.ProblemError{Status: http.StatusForbidden}
	response, _ = feedbackVisit(t, client, http.MethodGet, "/__tnl/feedback", httpaccess.VisitorTokenCookie+"="+token.Reveal())
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("local visit observation overrode control's current feedback denial")
	}
	control.err = nil
	for _, cookie := range []string{"", httpaccess.BrowserCookieName + "=" + visitorfixture.BrowserCookie} {
		response, _ = feedbackVisit(t, client, http.MethodGet, "/__tnl/feedback", cookie)
		if response.StatusCode != http.StatusForbidden {
			t.Fatal("identity-only sign-in granted restricted feedback access", response.StatusCode)
		}
	}
}

func TestFeedbackEvidenceIsBoundedAndExcludesReadiness(t *testing.T) {
	asset, path := toolbar.Script()
	runtime := &feedbackRuntime{browsers: make(map[[32]byte]*browserTrail), asset: asset, assetPath: path}
	probe := runtime.prepareBrowser(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/health", nil))
	runtime.observe(httpstream.WithReadinessProbe(probe), 500)
	if len(runtime.browsers) != 0 {
		t.Fatal("readiness created browser failure evidence")
	}
	for range maximumFeedbackBrowsers + 1 {
		response := httptest.NewRecorder()
		request := runtime.prepareBrowser(response, httptest.NewRequest(http.MethodGet, "/failed?secret=private", nil))
		for range maximumFailedRequests + 1 {
			runtime.observe(request, http.StatusInternalServerError)
		}
		cookie := response.Result().Cookies()[0]
		evidence := httptest.NewRequest(http.MethodGet, "/__tnl/feedback/evidence", nil)
		evidence.AddCookie(cookie)
		if got := runtime.evidenceForBrowser(evidence); len(got) != maximumFailedRequests || got[0].Path != "/failed" {
			t.Fatal("feedback evidence exceeded its per-browser bound or included a query", got)
		}
		runtime.observe(httpstream.WithReadinessProbe(request), 500)
	}
	if len(runtime.browsers) != maximumFeedbackBrowsers {
		t.Fatal("feedback retained an unbounded browser history", len(runtime.browsers))
	}
}

func TestFeedbackAnonymousAccessStillRequiresTheIPPolicy(t *testing.T) {
	control := &feedbackControlStub{}
	client, policy, update, _ := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("reserved feedback reached the application")
	}), false, true, func(f *HTTP) { testFeedbackRuntime(t, f, control) })
	apply := func(anonymous bool, ip *ippolicy.Policy) {
		t.Helper()
		update.Anonymous, update.IP = anonymous, ip
		update.View.VisitorPolicyRevision++
		now := time.Now()
		update.View.ObservedAt, update.View.ValidUntil = now, now.Add(10*time.Second)
		if err := policy.Apply(policy.Begin(), update); err != nil {
			t.Fatal(err)
		}
	}
	apply(true, nil)
	response, _ := feedbackVisit(t, client, http.MethodGet, "/__tnl/feedback", "")
	if response.StatusCode != http.StatusOK || !control.page.Access.VisitAllowed || control.page.Access.SourceIp == nil || *control.page.Access.SourceIp != "192.0.2.1" {
		t.Fatal("anonymous feedback lost its current policy or validated source", response.StatusCode, control.page)
	}
	key := [32]byte{1}
	entry, err := ippolicy.Hash(key, netip.MustParsePrefix("203.0.113.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	ip, err := ippolicy.New(key, []ippolicy.Entry{entry})
	if err != nil {
		t.Fatal(err)
	}
	control.page = controlv1.PreviewPageFeedbackRequest{}
	apply(true, &ip)
	response, _ = feedbackVisit(t, client, http.MethodGet, "/__tnl/feedback", "")
	if response.StatusCode == http.StatusOK || control.page.PreviewId != "" {
		t.Fatal("anonymous feedback bypassed its source-IP filter", response.StatusCode)
	}
	apply(false, nil)
	response, _ = feedbackVisit(t, client, http.MethodGet, "/__tnl/feedback", httpaccess.BrowserCookieName+"="+visitorfixture.BrowserCookie)
	if response.StatusCode != http.StatusForbidden || control.page.PreviewId != "" {
		t.Fatal("identity-only sign-in granted restricted feedback access")
	}
}

func TestFeedbackReadinessSkipsInjectionAndEvidence(t *testing.T) {
	control := &feedbackControlStub{}
	var runtime *feedbackRuntime
	var proof *httpaccess.ReadinessProof
	var status atomic.Int32
	client, _, _, _ := serviceHTTPConfiguredFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(httpstream.ReadinessProbeHeader) != "" || r.Header.Get("Accept-Encoding") != "gzip" {
			t.Error("feedback hooks exposed the readiness secret or changed compression")
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(int(status.Load()))
		_, _ = io.WriteString(w, "<html><head></head><body>health</body></html>")
	}), false, false, func(f *HTTP) {
		runtime = testFeedbackRuntime(t, f, control)
		var err error
		proof, err = httpaccess.NewReadinessProof(httpaccess.ReadinessRun{Subject: f.Subject, ID: f.RunID, Number: uint64(f.Number), Hostname: f.Hostname}, "/health")
		if err != nil {
			t.Fatal(err)
		}
		f.ReadinessProof = proof
		f.probes, err = requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Concurrency: new(4)})
		if err != nil {
			t.Fatal(err)
		}
	})
	for _, want := range []int{http.StatusOK, http.StatusInternalServerError} {
		status.Store(int32(want))
		secret, err := proof.Renew()
		if err != nil {
			t.Fatal(err)
		}
		request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://preview.example.test/health", nil)
		request.Header.Set(httpstream.ReadinessProbeHeader, secret)
		request.Header.Set("Accept-Encoding", "gzip")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != want || strings.Contains(string(body), runtime.assetPath) || len(response.Cookies()) != 0 || len(runtime.browsers) != 0 {
			t.Fatal("readiness injected a toolbar, set a tracking cookie, or recorded evidence", response.StatusCode, string(body), err)
		}
	}
}

func TestFeedbackRunCompositionKeepsDirectServiceFacts(t *testing.T) {
	cfg, control := lifecycleFixture(t)
	approved, err := control.GetPublisherService(t.Context(), cfg.ServiceID, "")
	if err != nil {
		t.Fatal(err)
	}
	approved.Protocol, approved.Endpoint.Port = controlv1.ServiceProtocolHTTP, 443
	control.approved = &approved
	cfg.Feedback, cfg.PreviewID, cfg.ProjectService, cfg.ProjectRoot = true, "pv_0123456789abcdefghijkl", "web", t.TempDir()
	cfg.FeedbackProjectID = strings.Repeat("a", 64)
	prepared, err := newManagedPrepared(control.prep, approved, cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, closeRun, err := configureServiceRun(t.Context(), cfg, prepared, control.setup, control, cfg.State, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := closeRun(); err != nil {
			t.Error("close configured run", err)
		}
	}()
	visitor := prepared.managedVisitor(tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{PublicService: &tunnelv1.PublicServiceAdmission{DestinationPort: 443}}}, netip.MustParseAddrPort("192.0.2.10:40000"), func(context.Context) error { return nil })
	httpVisitor, ok := visitor.(servicestream.HTTPVisitor)
	if !ok {
		t.Fatal("HTTP service did not compose its existing HTTP frontend")
	}
	frontend := httpVisitor.Frontend.(HTTP)
	feedback, _ := frontend.feedback.(*feedbackRuntime)
	if feedback == nil || feedback.previewID != cfg.PreviewID || feedback.service != cfg.ProjectService || feedback.projectRoot != cfg.ProjectRoot ||
		feedback.projectID != cfg.FeedbackProjectID ||
		feedback.serviceID != control.setup.ServiceId || feedback.runID != control.setup.ServiceRunId || feedback.number != control.setup.RunNumber ||
		feedback.token.String() != control.setup.RunToken || frontend.browser.PreviewID != cfg.PreviewID ||
		frontend.ResponseHooks.ModifyHTML == nil || frontend.ResponseHooks.ObserveStatus == nil {
		t.Fatal("feedback lost the service run's direct metadata or HTTP hooks")
	}
}

var _ FeedbackClient = (*clientcontrol.Client)(nil)
var _ HTTPControl = (*clientcontrol.Client)(nil)
