package publisher

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/tnldotdev/tnl/internal/browserfonts"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	publisherv1 "github.com/tnldotdev/tnl/pkg/api/publisher/browser/v1"
)

func (f *feedbackRuntime) reviewerAccess(request *http.Request, denied bool) (controlv1.FeedbackReviewerAccess, bool) {
	result := controlv1.FeedbackReviewerAccess{VisitAllowed: !denied}
	if host, _, err := net.SplitHostPort(request.RemoteAddr); err == nil {
		result.SourceIp = &host
	}
	if session, ok := request.Context().Value(visitorSessionKey{}).(*visitorSession); ok && session.visitor.Source.IsValid() {
		source := session.visitor.Source.Addr().Unmap().String()
		result.SourceIp = &source
	}
	if token := request.Header.Get(shareAccessHeaderName); token != "" {
		if id, secret, found := strings.Cut(token, "."); found && opaqueid.Valid(id, opaqueid.SharePrefix) {
			result.ShareId, result.ShareSecret = &id, &secret
		}
	}
	if _, verified := request.Context().Value(browserIdentityKey{}).(controlv1.BrowserAccessResponse); verified {
		if cookie, err := request.Cookie(browserAccessCookieName); err == nil {
			secret := cookie.Value
			result.BrowserCookieSecret = &secret
		}
	}
	if result.ShareSecret != nil {
		return result, true
	}
	cookie, err := request.Cookie(shareCookieName)
	if err != nil {
		return result, result.VisitAllowed || result.ShareSecret != nil || result.BrowserCookieSecret != nil
	}
	id, secret, found := strings.Cut(cookie.Value, ".")
	if !found || !opaqueid.Valid(id, opaqueid.SharePrefix) {
		return result, result.VisitAllowed || result.ShareSecret != nil || result.BrowserCookieSecret != nil
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
		httpjson.Write(response, http.StatusOK, publisherv1.BrowserFeedbackEvidence{SchemaVersion: 1, FailedRequests: f.evidenceForBrowser(request)})
		return true
	}
	access, ok := f.reviewerAccess(request, denied)
	if !ok {
		http.Error(response, "feedback requires a current share", http.StatusForbidden)
		return true
	}
	f.handlerOnce.Do(func() { f.handler = newFeedbackHandler(f) })
	request = request.WithContext(context.WithValue(request.Context(), feedbackAccessContextKey{}, access))
	f.handler.ServeHTTP(response, request)
	return true
}

func newFeedbackHandler(runtime *feedbackRuntime) http.Handler {
	return publisherv1.HandlerWithOptions(&feedbackHTTP{runtime: runtime}, publisherv1.StdHTTPServerOptions{
		ErrorHandlerFunc: func(response http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(response, "invalid feedback parameter", http.StatusBadRequest)
		},
	})
}

func (f *feedbackRuntime) list(response http.ResponseWriter, request *http.Request, access controlv1.FeedbackReviewerAccess, params publisherv1.ListBrowserFeedbackParams) {
	path := ""
	if params.Path != nil {
		path = *params.Path
	}
	if len(path) > 2048 || path != "" && path[0] != '/' {
		http.Error(response, "provide the page path", http.StatusBadRequest)
		return
	}
	input := controlv1.PreviewPageFeedbackRequest{
		PreviewId: f.previewID, PublishRunNumber: int64(f.version), Access: access,
	}
	if path != "" {
		input.PagePath = &path
	}
	if params.State != nil && *params.State != "" {
		state := string(*params.State)
		if state != "open" && state != "resolved" {
			http.Error(response, "invalid feedback state", http.StatusBadRequest)
			return
		}
		value := controlv1.FeedbackThreadState(state)
		input.State = &value
	}
	if params.Cursor != nil && *params.Cursor != "" {
		cursor := *params.Cursor
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
	var input publisherv1.BrowserFeedbackReportRequest
	if !readFeedbackInput(response, request, &input) || input.SchemaVersion != 1 || input.Text == "" || input.PagePath == "" {
		http.Error(response, "provide feedback text and a page path", http.StatusBadRequest)
		return
	}
	key := request.Header.Get("Idempotency-Key")
	if key == "" || len(key) > 128 {
		http.Error(response, "provide an idempotency key", http.StatusBadRequest)
		return
	}
	source, err := f.sourceState(request.Context())
	if err != nil {
		f.writeResult(response, nil, err)
		return
	}
	body := controlv1.CreateFeedbackReportRequest{
		PageTitle: input.PageTitle,
		Access:    access, SourceAtReport: source, Anchor: input.Anchor,
		Evidence: input.Evidence, PagePath: input.PagePath, PreviewId: f.previewID,
		PublishRunNumber: int64(f.version), Service: f.service,
	}
	body.Report.Text = input.Text
	if input.DisplayName != nil && *input.DisplayName != "" {
		body.Report.DisplayName = input.DisplayName
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

func (f *feedbackRuntime) events(response http.ResponseWriter, request *http.Request, id string, access controlv1.FeedbackReviewerAccess, after *int64) {
	body := controlv1.ReviewerFeedbackReadRequest{
		PreviewId: f.previewID, PublishRunNumber: int64(f.version), Access: access,
	}
	if after != nil {
		if *after < 0 {
			http.Error(response, "invalid feedback cursor", http.StatusBadRequest)
			return
		}
		body.AfterCursor = after
	}
	result, err := f.client.ListReviewerFeedbackEvents(request.Context(), f.runID, id, body, f.token)
	f.writeResult(response, result, err)
}

func (f *feedbackRuntime) reply(response http.ResponseWriter, request *http.Request, id string, access controlv1.FeedbackReviewerAccess) {
	var input publisherv1.BrowserFeedbackEventRequest
	if !readFeedbackInput(response, request, &input) || input.SchemaVersion != 1 {
		http.Error(response, "invalid feedback event", http.StatusBadRequest)
		return
	}
	key := request.Header.Get("Idempotency-Key")
	if key == "" || len(key) > 128 {
		http.Error(response, "provide an idempotency key", http.StatusBadRequest)
		return
	}
	if !input.Type.Valid() {
		http.Error(response, "invalid feedback event", http.StatusBadRequest)
		return
	}
	body := controlv1.AppendReviewerFeedbackEventRequest{
		Access: access, PublishRunNumber: int64(f.version), Type: controlv1.FeedbackEventType(input.Type),
	}
	if input.Text != nil && *input.Text != "" {
		body.Text = input.Text
	}
	result, err := f.client.AppendReviewerFeedbackEvent(request.Context(), f.runID, id, key, body, f.token)
	f.writeResult(response, result, err)
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
		var problem *clientcontrol.ProblemError
		switch {
		case errors.Is(err, clientcontrol.ErrUnauthenticated):
			message, status = "feedback requires sign-in; sign in and retry", http.StatusUnauthorized
		case errors.Is(err, clientcontrol.ErrNotFound):
			message, status = "feedback thread not found", http.StatusNotFound
		case errors.Is(err, clientcontrol.ErrStatusConflict):
			message, status = "feedback changed; reload and retry", http.StatusConflict
		case errors.Is(err, clientcontrol.ErrRateLimited):
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
