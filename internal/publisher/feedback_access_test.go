package publisher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/api/publisherv1"
)

func TestFeedbackAccessRealPublisherKeepsScopePolicyAndStaleCredentials(t *testing.T) {
	contents, err := os.ReadFile("../../api/fixtures/publisher/v1/thread.json")
	if err != nil {
		t.Fatal(err)
	}
	var thread controlv1.FeedbackThread
	if err := json.Unmarshal(contents, &thread); err != nil {
		t.Fatal(err)
	}
	const token = credentials.PublishRunToken("publisher-secret")
	valid := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	expired := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	shareSecret := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	const shareID = "shr_0123456789abcdefghijkl"
	var required, identityUnavailable, policyUnavailable atomic.Bool
	var writeCalls atomic.Int64
	control := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token.String() {
			t.Error("publisher authentication was lost")
		}
		problem := func(status int, code controlv1.ProblemCode) {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(controlv1.Problem{Code: code, Status: status, Title: "private-upstream-secret"})
		}
		prefix := "/v1/publish-runs/" + thread.Scope.PublishRunId
		switch r.URL.Path {
		case prefix + "/browser/access":
			var body controlv1.BrowserAccessRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if identityUnavailable.Load() {
				problem(503, controlv1.Unavailable)
				return
			}
			if body.CookieSecret != valid {
				problem(403, controlv1.Forbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(controlv1.BrowserAccessResponse{IdentityId: "external-reviewer", DisplayName: "Sam", VisitAllowed: false})
		case prefix + "/feedback/access":
			var body controlv1.FeedbackAccessRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body.PreviewId != thread.Scope.PreviewId || body.PublishRunNumber != thread.Scope.PublishRunNumber {
				t.Errorf("browser selected metadata scope: %+v", body)
			}
			if body.Access.BrowserCookieSecret != nil && *body.Access.BrowserCookieSecret == expired {
				t.Error("expired cookie blocked an admitted metadata read")
			}
			if policyUnavailable.Load() {
				problem(503, controlv1.Unavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(controlv1.FeedbackAccess{RequireSignIn: required.Load()})
		case prefix + "/feedback/query":
			var body controlv1.PreviewPageFeedbackRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Error(err)
			}
			if body.Access.BrowserCookieSecret != nil && *body.Access.BrowserCookieSecret == expired {
				t.Error("stale credential blocked an IP/share read")
			}
			_ = json.NewEncoder(w).Encode(controlv1.FeedbackThreadPage{SchemaVersion: 1, Threads: []controlv1.FeedbackThreadSummary{}, EventCursor: 0})
		default:
			if !strings.HasPrefix(r.URL.Path, prefix+"/feedback") {
				t.Errorf("unexpected control request: %s", r.URL.Path)
				http.NotFound(w, r)
				return
			}
			writeCalls.Add(1)
			var access controlv1.FeedbackReviewerAccess
			if r.URL.Path == prefix+"/feedback" {
				var body controlv1.CreateFeedbackReportRequest
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				access = body.Access
				if body.PreviewId != thread.Scope.PreviewId {
					t.Error("report escaped publisher preview")
				}
			} else {
				var body controlv1.AppendReviewerFeedbackEventRequest
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				access = body.Access
			}
			if access.BrowserCookieSecret != nil && *access.BrowserCookieSecret != valid {
				problem(403, controlv1.Forbidden)
				return
			}
			if required.Load() && access.BrowserCookieSecret == nil {
				problem(401, controlv1.FeedbackSignInRequired)
				return
			}
			result := thread
			result.Report.Author = nil
			if access.BrowserCookieSecret != nil {
				result.Report.Author = &controlv1.FeedbackAuthor{Verified: true, IdentityId: new("external-reviewer"), DisplayName: "Sam"}
			}
			_ = json.NewEncoder(w).Encode(result)
		}
	}))
	defer control.Close()
	client, err := controlclient.New(control.URL, control.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	appCookies := make(chan string, 1)
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		appCookies <- r.Header.Get("Cookie")
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><head></head><body><button>Save</button></body></html>"))
	}))
	defer app.Close()
	runtime, err := newFeedbackRuntime(Config{Feedback: true, Control: client, PreviewID: thread.Scope.PreviewId, Service: "web", ProjectRoot: t.TempDir()}, controlv1.PublishRunSetup{PublicUrl: controlv1.PublicURL{Id: thread.Scope.PublicUrlId}, PublishRun: controlv1.PublishRun{Id: thread.Scope.PublishRunId, PublishRunNumber: thread.Scope.PublishRunNumber}}, token)
	if err != nil {
		t.Fatal(err)
	}
	shares := &shareAccess{confirmed: time.Now(), shares: map[string]cachedShare{shareID: {expiresAt: time.Now().Add(time.Hour), cookies: map[[32]byte]struct{}{sha256.Sum256(bytes.Repeat([]byte{3}, 32)): {}}}}}
	runtime.browser = &browserAccess{client: client, previewID: runtime.previewID, publicURLID: runtime.publicURLID, runID: runtime.runID, version: runtime.version, token: token, controlURL: control.URL}
	server, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "web.example.test", Target: app.URL, Feedback: runtime, ShareAccess: shares, BrowserAccess: runtime.browser})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	serve := func(method, path, body, cookies string, denied bool, status int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Host, r.TLS = "web.example.test", &tls.ConnectionState{ServerName: "web.example.test"}
		r.Header.Set("Idempotency-Key", "test-write")
		if cookies != "" {
			r.Header.Set("Cookie", cookies)
		}
		r = r.WithContext(context.WithValue(r.Context(), denialContextKey{}, denied))
		w := httptest.NewRecorder()
		server.http.Handler.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("%s %s = %d %s, want %d", method, path, w.Code, w.Body.String(), status)
		}
		if strings.Contains(w.Body.String(), "private-upstream-secret") {
			t.Fatal("control error body leaked")
		}
		return w
	}
	metadata := func(cookies string, denied bool, state publisherv1.BrowserFeedbackAccessIdentityState) publisherv1.BrowserFeedbackAccess {
		t.Helper()
		w := serve("GET", "/__tnl/feedback/access?preview_id=forged&public_url_id=forged", "", cookies, denied, 200)
		var result publisherv1.BrowserFeedbackAccess
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.IdentityState != state || result.RequireSignIn != required.Load() || !result.SignInAvailable || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("metadata=%+v", result)
		}
		return result
	}
	metadata("", false, publisherv1.Anonymous)
	required.Store(true)
	metadata("", false, publisherv1.Anonymous)
	report := `{"schema_version":1,"text":"Review","page_path":"/","evidence":{"schema_version":1,"actions":[],"failed_requests":[]}}`
	serve("POST", "/__tnl/feedback", report, "", false, 401)
	for _, admission := range []struct {
		cookie string
		denied bool
	}{{browserAccessCookieName + "=" + valid, false}, {browserAccessCookieName + "=" + valid + "; " + shareCookieName + "=" + shareID + "." + shareSecret, true}} {
		if result := metadata(admission.cookie, admission.denied, publisherv1.SignedIn); result.Identity == nil || result.Identity.IdentityId != "external-reviewer" {
			t.Fatalf("external identity=%+v", result)
		}
		created := serve("POST", "/__tnl/feedback", report, admission.cookie, admission.denied, 200)
		if !strings.Contains(created.Body.String(), `"verified":true`) {
			t.Fatal("external reviewer lost verified attribution")
		}
	}
	// a cookie change after UI preflight cannot retry under another author.
	serve("POST", "/__tnl/feedback", strings.TrimSuffix(report, "}")+`,"posting_identity":"anonymous"}`, browserAccessCookieName+"="+valid, false, 409)
	serve("POST", "/__tnl/feedback", strings.TrimSuffix(report, "}")+`,"posting_identity":"identity:someone-else"}`, browserAccessCookieName+"="+valid, false, 409)
	serve("POST", "/__tnl/feedback/"+thread.Id+"/events", `{"schema_version":1,"type":"reply","text":"Note","posting_identity":"identity:someone-else"}`, browserAccessCookieName+"="+valid, false, 409)
	for _, cookie := range []string{browserAccessCookieName + "=" + expired, browserAccessCookieName + "=not-base64", browserAccessCookieName + "=\"broken"} {
		metadata(cookie, false, publisherv1.Expired)
		serve("GET", "/__tnl/feedback", "", cookie, false, 200)
		for _, action := range []string{"report", "reply", "thread.resolved", "thread.reopened"} {
			path, body := "/__tnl/feedback", report
			if action != "report" {
				path += "/" + thread.Id + "/events"
				body = `{"schema_version":1,"type":"` + action + `","text":"Note"}`
			}
			status := 401
			if cookie == browserAccessCookieName+"="+expired {
				status = 403
			}
			serve("POST", path, body, cookie, false, status)
		}
	}
	if writeCalls.Load() != 7 {
		t.Fatalf("invalid credentials reached a write or stale credentials were dropped: %d", writeCalls.Load())
	}
	identityUnavailable.Store(true)
	serve("GET", "/__tnl/feedback/access", "", browserAccessCookieName+"="+valid, false, 503)
	identityUnavailable.Store(false)
	policyUnavailable.Store(true)
	serve("GET", "/__tnl/feedback/access", "", "", false, 503)
	policyUnavailable.Store(false)
	required.Store(false)
	originalBrowser := runtime.browser
	runtime.browser = nil
	guest := serve("GET", "/__tnl/feedback/access", "", "", false, 200)
	if !strings.Contains(guest.Body.String(), `"sign_in_available":false`) || !strings.Contains(guest.Body.String(), `"require_sign_in":false`) {
		t.Fatalf("guest metadata=%s", guest.Body.String())
	}
	runtime.browser = originalBrowser
	serve("GET", "/", "", "app_session=keep; "+browserAccessCookieName+"="+valid, false, 200)
	if cookie := <-appCookies; cookie != "app_session=keep" {
		t.Fatalf("browser credential reached local app: %q", cookie)
	}
	login := serve("GET", "/__tnl/team/login?return=%2Fpreview%3Ftab%3Done", "", "", false, 303)
	if !strings.Contains(login.Header().Get("Location"), "return_path=%2Fpreview%3Ftab%3Done") {
		t.Fatalf("login changed return path: %s", login.Header().Get("Location"))
	}
}
