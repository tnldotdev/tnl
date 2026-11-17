//go:build !js || !wasm

package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"

	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"

	"github.com/tnldotdev/tnl/internal/browserfonts"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	publisherv1 "github.com/tnldotdev/tnl/pkg/api/publisher/browser/v1"
)

func (f *feedbackRuntime) reviewerAccess(request *http.Request, authorization feedbackAuthorization) (controlv1.FeedbackReviewerAccess, bool) {
	result := controlv1.FeedbackReviewerAccess{VisitAllowed: authorization.allowed, VisitProof: authorization.proof}
	source, err := netip.ParseAddrPort(request.RemoteAddr)
	if err != nil || source.Addr().Zone() != "" {
		return result, false
	}
	address := source.Addr().Unmap().String()
	result.SourceIp = &address
	for key := range request.Header {
		if strings.EqualFold(key, httpaccess.ShareHeaderName) {
			return result, false
		}
	}
	if httpaccess.SuppliedCookieCount(request, httpaccess.BrowserCookieName) != 0 {
		cookies := request.CookiesNamed(httpaccess.BrowserCookieName)
		if len(cookies) != 1 || httpaccess.SuppliedCookieCount(request, httpaccess.BrowserCookieName) != 1 {
			return result, false
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(cookies[0].Value)
		if err != nil || len(raw) != 32 {
			return result, false
		}
		// control checks this browser-session fact and derives the author. the
		// locally verified visitor token supplies no verified identity snapshot.
		secret := cookies[0].Value
		result.BrowserCookieSecret = &secret
	}
	count := httpaccess.SuppliedCookieCount(request, httpaccess.ShareCookieName)
	if count != 0 {
		cookies := request.CookiesNamed(httpaccess.ShareCookieName)
		if count != 1 || len(cookies) != 1 {
			return result, false
		}
		id, secret, found := strings.Cut(cookies[0].Value, ".")
		raw, err := base64.RawURLEncoding.Strict().DecodeString(secret)
		if !found || !opaqueid.Valid(id, opaqueid.SharePrefix) || err != nil || len(raw) != 32 {
			return result, false
		}
		// validate supplied cookies, but never add another permission source
		// when admission already selected an explicit proof.
		if result.VisitProof == nil {
			result.ShareId, result.CookieSecret = &id, &secret
		}
	}
	return result, result.VisitAllowed || result.CookieSecret != nil || result.BrowserCookieSecret != nil
}

func (f *feedbackRuntime) handle(response http.ResponseWriter, request *http.Request, authorization feedbackAuthorization) bool {
	if !strings.HasPrefix(request.URL.Path, "/__tnl/feedback") {
		return false
	}
	access, ok := f.reviewerAccess(request, authorization)
	if !ok {
		http.Error(response, "feedback requires a current share", http.StatusForbidden)
		return true
	}
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
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Referrer-Policy", "no-referrer")
	if request.URL.Path == "/__tnl/feedback/evidence" && request.Method == http.MethodGet {
		httpjson.Write(response, http.StatusOK, publisherv1.BrowserFeedbackEvidence{SchemaVersion: 1, FailedRequests: f.evidenceForBrowser(request)})
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
		PreviewId: f.previewID, RunNumber: f.number, Access: access,
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
	local, err := f.local(request.Context(), access)
	if err != nil {
		f.writeResult(response, nil, err)
		return
	}
	result, err := local.List(request.Context(), f.serviceID, path, feedbackValue(input.State), feedbackValue(input.Cursor))
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
		RunNumber: f.number, Service: f.service,
	}
	body.Report.Text = input.Text
	local, err := f.local(request.Context(), access)
	if err != nil {
		f.writeResult(response, nil, err)
		return
	}
	created, err := local.Create(request.Context(), f.serviceID, f.runID, key, body)
	f.writeResult(response, created, err)
}

func (f *feedbackRuntime) read(response http.ResponseWriter, request *http.Request, id string, access controlv1.FeedbackReviewerAccess) {
	local, err := f.local(request.Context(), access)
	if err != nil {
		f.writeResult(response, nil, err)
		return
	}
	result, err := local.GetFeedbackThread(request.Context(), id)
	if err == nil && result.Scope.ServiceId != f.serviceID {
		err = clientstate.ErrFeedbackNotFound
	}
	f.writeResult(response, result, err)
}

func (f *feedbackRuntime) events(response http.ResponseWriter, request *http.Request, id string, access controlv1.FeedbackReviewerAccess, after *int64) {
	body := controlv1.ReviewerFeedbackReadRequest{
		PreviewId: f.previewID, RunNumber: f.number, Access: access,
	}
	if after != nil {
		if *after < 0 {
			http.Error(response, "invalid feedback cursor", http.StatusBadRequest)
			return
		}
		body.AfterCursor = after
	}
	local, err := f.local(request.Context(), access)
	if err != nil {
		f.writeResult(response, nil, err)
		return
	}
	var cursor uint64
	if body.AfterCursor != nil {
		cursor = uint64(*body.AfterCursor)
	}
	result, err := local.Events(request.Context(), f.serviceID, id, cursor)
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
		Access: access, RunNumber: f.number, Type: controlv1.ReviewerFeedbackEventInputType(input.Type),
	}
	if input.Text != nil && *input.Text != "" {
		body.Text = input.Text
	}
	local, err := f.local(request.Context(), access)
	if err != nil {
		f.writeResult(response, nil, err)
		return
	}
	result, err := local.AppendFeedbackEvent(request.Context(), id, key, controlv1.AppendFeedbackEventRequest{
		Type: controlv1.FeedbackEventInputType(body.Type), Text: body.Text,
	})
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

func feedbackValue[T ~string](value *T) string {
	if value == nil {
		return ""
	}
	return string(*value)
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
		case errors.Is(err, clientcontrol.ErrNotFound), errors.Is(err, clientstate.ErrFeedbackNotFound):
			message, status = "feedback thread not found", http.StatusNotFound
		case errors.Is(err, clientcontrol.ErrStatusConflict), errors.Is(err, clientstate.ErrFeedbackState), errors.Is(err, clientstate.ErrFeedbackIdempotency):
			message, status = "feedback changed; reload and retry", http.StatusConflict
		case errors.Is(err, clientcontrol.ErrRateLimited):
			message, status = "too many feedback requests; retry shortly", http.StatusTooManyRequests
		case errors.Is(err, clientstate.ErrFeedbackAccess):
			message, status = "feedback requires current access", http.StatusForbidden
		case errors.Is(err, clientstate.ErrFeedbackInvalid):
			message, status = "invalid feedback request; check the input", http.StatusBadRequest
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
