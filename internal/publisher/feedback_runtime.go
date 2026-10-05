package publisher

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/browserfonts"
	"github.com/tnldotdev/tnl/internal/checkoutmarker"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/feedbacktoolbar"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const (
	feedbackBrowserCookieName = "__Host-tnl-feedback-browser"
	maximumFeedbackBrowsers   = 128
	maximumFailedRequests     = 20
)

type feedbackClient interface {
	CreateFeedbackReport(context.Context, string, string, controlv1.CreateFeedbackReportRequest, credentials.PublishRunToken) (controlv1.FeedbackThread, error)
	ListPreviewPageFeedback(context.Context, string, controlv1.PreviewPageFeedbackRequest, credentials.PublishRunToken) (controlv1.FeedbackThreadPage, error)
	GetReviewerFeedbackThread(context.Context, string, string, controlv1.ReviewerFeedbackReadRequest, credentials.PublishRunToken) (controlv1.FeedbackThread, error)
	ListReviewerFeedbackEvents(context.Context, string, string, controlv1.ReviewerFeedbackReadRequest, credentials.PublishRunToken) (controlv1.FeedbackEventPage, error)
	AppendReviewerFeedbackEvent(context.Context, string, string, string, controlv1.AppendReviewerFeedbackEventRequest, credentials.PublishRunToken) (controlv1.FeedbackEvent, error)
}

type feedbackRequestContextKey struct{}

type feedbackRequestContext struct {
	browser [32]byte
	method  string
	path    string
	started time.Time
}

type failedRequest struct {
	Method     string `json:"method"`
	Path       string `json:"path"`
	Status     int    `json:"status"`
	DurationMS int    `json:"duration_ms"`
}

type browserTrail struct {
	lastSeen time.Time
	failures []failedRequest
}

type feedbackRuntime struct {
	client      feedbackClient
	previewID   string
	publicURLID string
	service     string
	projectRoot string
	runID       string
	version     uint64
	token       credentials.PublishRunToken
	mu          sync.Mutex
	browsers    map[[32]byte]*browserTrail
	asset       []byte
	assetPath   string
	demo        bool
}

func newFeedbackRuntime(config Config, setup controlv1.PublishRunSetup, token credentials.PublishRunToken) (*feedbackRuntime, error) {
	if !config.Feedback {
		return nil, nil
	}
	client, ok := config.Control.(feedbackClient)
	if !ok || config.PreviewID == "" || config.Service == "" || !config.Demo && config.ProjectRoot == "" {
		return nil, errors.New("publisher: feedback requires a configured preview, project service, and control client")
	}
	asset, assetPath := feedbacktoolbar.Script()
	return &feedbackRuntime{
		demo:   config.Demo,
		client: client, previewID: config.PreviewID, publicURLID: setup.PublicUrl.Id,
		service: config.Service, projectRoot: config.ProjectRoot,
		runID: setup.PublishRun.Id, version: uint64(setup.PublishRun.PublishRunNumber), token: token,
		browsers: make(map[[32]byte]*browserTrail), asset: asset, assetPath: assetPath,
	}, nil
}

func (f *feedbackRuntime) modifyResponse(response *http.Response) error {
	return feedbacktoolbar.Inject(response)
}

func (f *feedbackRuntime) prepareBrowser(response http.ResponseWriter, request *http.Request) *http.Request {
	var raw []byte
	if cookie, err := request.Cookie(feedbackBrowserCookieName); err == nil {
		raw, _ = base64.RawURLEncoding.DecodeString(cookie.Value)
	}
	if len(raw) != 32 {
		raw = make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return request
		}
		http.SetCookie(response, &http.Cookie{
			Name: feedbackBrowserCookieName, Value: base64.RawURLEncoding.EncodeToString(raw),
			Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
			Expires: time.Now().Add(24 * time.Hour),
		})
	}
	key := sha256.Sum256(raw)
	return request.WithContext(context.WithValue(request.Context(), feedbackRequestContextKey{}, feedbackRequestContext{
		browser: key, method: request.Method, path: request.URL.Path, started: time.Now(),
	}))
}

func (f *feedbackRuntime) observe(request *http.Request, status int) {
	if request == nil || status > 0 && status < 400 {
		return
	}
	info, ok := request.Context().Value(feedbackRequestContextKey{}).(feedbackRequestContext)
	if !ok || !strings.HasPrefix(info.path, "/") || len(info.path) > 2048 {
		return
	}
	entry := failedRequest{
		Method: info.method, Path: info.path, Status: status,
		DurationMS: int(min(time.Since(info.started).Milliseconds(), 600000)),
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	trail := f.browsers[info.browser]
	if trail == nil {
		if len(f.browsers) >= maximumFeedbackBrowsers {
			var oldest [32]byte
			var at time.Time
			for key, candidate := range f.browsers {
				if at.IsZero() || candidate.lastSeen.Before(at) {
					oldest, at = key, candidate.lastSeen
				}
			}
			delete(f.browsers, oldest)
		}
		trail = &browserTrail{}
		f.browsers[info.browser] = trail
	}
	trail.lastSeen = time.Now()
	trail.failures = append(trail.failures, entry)
	if len(trail.failures) > maximumFailedRequests {
		trail.failures = trail.failures[len(trail.failures)-maximumFailedRequests:]
	}
}

func (f *feedbackRuntime) evidenceForBrowser(request *http.Request) []failedRequest {
	result := make([]failedRequest, 0)
	cookie, err := request.Cookie(feedbackBrowserCookieName)
	if err != nil {
		return result
	}
	raw, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || len(raw) != 32 {
		return result
	}
	key := sha256.Sum256(raw)
	f.mu.Lock()
	defer f.mu.Unlock()
	if trail := f.browsers[key]; trail != nil && time.Since(trail.lastSeen) < 15*time.Minute {
		result = append(result, trail.failures...)
	}
	return result
}

func (f *feedbackRuntime) reviewerAccess(request *http.Request, denied bool) (controlv1.FeedbackReviewerAccess, bool) {
	result := controlv1.FeedbackReviewerAccess{AllowedIp: !denied}
	if !denied {
		return result, true
	}
	cookie, err := request.Cookie(shareCookieName)
	if err != nil {
		return result, false
	}
	id, secret, found := strings.Cut(cookie.Value, ".")
	if !found || !opaqueid.Valid(id, opaqueid.SharePrefix) {
		return result, false
	}
	result.ShareId, result.CookieSecret = &id, &secret
	return result, true
}

func (f *feedbackRuntime) handle(response http.ResponseWriter, request *http.Request, denied bool) bool {
	if request.Method == http.MethodGet && request.URL.Path == "/__tnl/feedback/fira-code.woff2" {
		response.Header().Set("Content-Type", "font/woff2")
		response.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = response.Write(browserfonts.Latin)
		return true
	}
	if request.URL.Path == f.assetPath {
		if request.Method != http.MethodGet {
			response.WriteHeader(http.StatusMethodNotAllowed)
			return true
		}
		response.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		response.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		_, _ = response.Write(f.asset)
		return true
	}
	if !strings.HasPrefix(request.URL.Path, "/__tnl/feedback") {
		return false
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Referrer-Policy", "no-referrer")
	if request.URL.Path == "/__tnl/feedback/evidence" && request.Method == http.MethodGet {
		httpjson.Write(response, http.StatusOK, struct {
			SchemaVersion  int             `json:"schema_version"`
			FailedRequests []failedRequest `json:"failed_requests"`
		}{SchemaVersion: 1, FailedRequests: f.evidenceForBrowser(request)})
		return true
	}
	access, ok := f.reviewerAccess(request, denied)
	if !ok {
		http.Error(response, "feedback requires a current share", http.StatusForbidden)
		return true
	}
	if request.URL.Path == "/__tnl/feedback" {
		switch request.Method {
		case http.MethodGet:
			f.list(response, request, access)
		case http.MethodPost:
			f.create(response, request, access)
		default:
			response.WriteHeader(http.StatusMethodNotAllowed)
		}
		return true
	}
	selected := strings.TrimPrefix(request.URL.Path, "/__tnl/feedback/")
	id, suffix, hasSuffix := strings.Cut(selected, "/")
	if !opaqueid.Valid(id, opaqueid.FeedbackPrefix) {
		http.NotFound(response, request)
		return true
	}
	if !hasSuffix && request.Method == http.MethodGet {
		f.read(response, request, id, access)
		return true
	}
	if suffix == "events" {
		switch request.Method {
		case http.MethodGet:
			f.events(response, request, id, access)
		case http.MethodPost:
			f.reply(response, request, id, access)
		default:
			response.WriteHeader(http.StatusMethodNotAllowed)
		}
		return true
	}
	http.NotFound(response, request)
	return true
}

func (f *feedbackRuntime) list(response http.ResponseWriter, request *http.Request, access controlv1.FeedbackReviewerAccess) {
	path := request.URL.Query().Get("path")
	if path == "" || len(path) > 2048 || path[0] != '/' {
		http.Error(response, "provide the page path", http.StatusBadRequest)
		return
	}
	input := controlv1.PreviewPageFeedbackRequest{
		PreviewId: f.previewID, PublishRunNumber: int64(f.version), PagePath: path, Access: access,
	}
	if cursor := request.URL.Query().Get("cursor"); cursor != "" {
		if !opaqueid.Valid(cursor, opaqueid.FeedbackPrefix) {
			http.Error(response, "invalid feedback cursor", http.StatusBadRequest)
			return
		}
		input.Cursor = &cursor
	}
	result, err := f.client.ListPreviewPageFeedback(request.Context(), f.runID, input, f.token)
	f.writeResult(response, result, err)
}

func (f *feedbackRuntime) create(response http.ResponseWriter, request *http.Request, access controlv1.FeedbackReviewerAccess) {
	var input struct {
		SchemaVersion int                        `json:"schema_version"`
		Text          string                     `json:"text"`
		DisplayName   string                     `json:"display_name"`
		PagePath      string                     `json:"page_path"`
		Anchor        *controlv1.FeedbackAnchor  `json:"anchor,omitempty"`
		Evidence      controlv1.FeedbackEvidence `json:"evidence"`
	}
	if !readFeedbackInput(response, request, &input) || input.SchemaVersion != 1 || input.Text == "" || input.PagePath == "" {
		http.Error(response, "provide feedback text and a page path", http.StatusBadRequest)
		return
	}
	key := request.Header.Get("Idempotency-Key")
	if key == "" || len(key) > 128 {
		http.Error(response, "provide an idempotency key", http.StatusBadRequest)
		return
	}
	marker, err := f.checkout(request.Context())
	if err != nil {
		f.writeResult(response, nil, err)
		return
	}
	body := controlv1.CreateFeedbackReportRequest{
		Access: access, CheckoutAtReport: marker, Anchor: input.Anchor,
		Evidence: input.Evidence, PagePath: input.PagePath, PreviewId: f.previewID,
		PublishRunNumber: int64(f.version), Service: f.service,
	}
	body.Report.Text = input.Text
	if input.DisplayName != "" {
		body.Report.DisplayName = &input.DisplayName
	}
	created, err := f.client.CreateFeedbackReport(request.Context(), f.runID, key, body, f.token)
	f.writeResult(response, created, err)
}

func (f *feedbackRuntime) read(response http.ResponseWriter, request *http.Request, id string, access controlv1.FeedbackReviewerAccess) {
	result, err := f.client.GetReviewerFeedbackThread(request.Context(), f.runID, id, controlv1.ReviewerFeedbackReadRequest{
		PreviewId: f.previewID, PublishRunNumber: int64(f.version), Access: access,
	}, f.token)
	f.writeResult(response, result, err)
}

func (f *feedbackRuntime) events(response http.ResponseWriter, request *http.Request, id string, access controlv1.FeedbackReviewerAccess) {
	body := controlv1.ReviewerFeedbackReadRequest{
		PreviewId: f.previewID, PublishRunNumber: int64(f.version), Access: access,
	}
	if after := request.URL.Query().Get("after_cursor"); after != "" {
		value, err := strconv.ParseInt(after, 10, 64)
		if err != nil || value < 0 {
			http.Error(response, "invalid feedback cursor", http.StatusBadRequest)
			return
		}
		body.AfterCursor = &value
	}
	result, err := f.client.ListReviewerFeedbackEvents(request.Context(), f.runID, id, body, f.token)
	f.writeResult(response, result, err)
}

func (f *feedbackRuntime) reply(response http.ResponseWriter, request *http.Request, id string, access controlv1.FeedbackReviewerAccess) {
	var input struct {
		SchemaVersion int                         `json:"schema_version"`
		Type          controlv1.FeedbackEventType `json:"type"`
		Text          string                      `json:"text"`
	}
	if !readFeedbackInput(response, request, &input) || input.SchemaVersion != 1 {
		http.Error(response, "invalid feedback event", http.StatusBadRequest)
		return
	}
	key := request.Header.Get("Idempotency-Key")
	if key == "" || len(key) > 128 {
		http.Error(response, "provide an idempotency key", http.StatusBadRequest)
		return
	}
	if input.Type != controlv1.Reply && input.Type != controlv1.ThreadResolved && input.Type != controlv1.ThreadReopened {
		http.Error(response, "invalid feedback event", http.StatusBadRequest)
		return
	}
	body := controlv1.AppendReviewerFeedbackEventRequest{
		Access: access, PublishRunNumber: int64(f.version), Type: input.Type,
	}
	if input.Text != "" {
		body.Text = &input.Text
	}
	result, err := f.client.AppendReviewerFeedbackEvent(request.Context(), f.runID, id, key, body, f.token)
	f.writeResult(response, result, err)
}

func (f *feedbackRuntime) checkout(ctx context.Context) (controlv1.CheckoutMarker, error) {
	if !f.demo {
		return checkoutmarker.Capture(ctx, f.projectRoot)
	}
	digest := sha256.Sum256([]byte("demo/" + f.runID))
	encoded, err := json.Marshal(map[string]any{
		"schema_version": 1, "head_commit": "", "branch": "", "changed_files": []any{},
		"fingerprint": fmt.Sprintf("sha256:%x", digest), "complete": false,
	})
	if err != nil {
		return controlv1.CheckoutMarker{}, err
	}
	var marker controlv1.CheckoutMarker
	err = json.Unmarshal(encoded, &marker)
	return marker, err
}

func readFeedbackInput(response http.ResponseWriter, request *http.Request, target any) bool {
	request.Body = http.MaxBytesReader(response, request.Body, 64<<10)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return false
	}
	return decoder.Decode(new(any)) == io.EOF
}

func (f *feedbackRuntime) writeResult(response http.ResponseWriter, value any, err error) {
	if err != nil {
		// only a stable diagnostic is shown to the visitor. credentials and
		// submitted evidence never appear in an HTTP error body.
		message, status := "feedback request failed; retry", http.StatusServiceUnavailable
		var problem *controlclient.ProblemError
		switch {
		case errors.Is(err, controlclient.ErrNotFound):
			message, status = "feedback thread not found", http.StatusNotFound
		case errors.Is(err, controlclient.ErrStatusConflict):
			message, status = "feedback changed; reload and retry", http.StatusConflict
		case errors.Is(err, controlclient.ErrRateLimited):
			message, status = "too many feedback requests; retry shortly", http.StatusTooManyRequests
		case errors.As(err, &problem) && problem.Status == http.StatusForbidden:
			message, status = "feedback requires a current share", http.StatusForbidden
		case errors.As(err, &problem) && problem.Status == http.StatusBadRequest:
			message, status = "invalid feedback request; check the input", http.StatusBadRequest
		}
		http.Error(response, message, status)
		return
	}
	httpjson.Write(response, http.StatusOK, value)
}
