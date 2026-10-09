package publisher

import (
	"net/http"

	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/api/publisherv1"
)

type feedbackAccessContextKey struct{}

// feedbackHTTP binds generated routes after the publisher's preview access gate.
type feedbackHTTP struct{ runtime *feedbackRuntime }

var _ publisherv1.ServerInterface = (*feedbackHTTP)(nil)

func (h *feedbackHTTP) GetBrowserFeedbackAccess(response http.ResponseWriter, request *http.Request) {
	if access, ok := feedbackHTTPAccess(response, request); ok {
		h.runtime.access(response, request, access)
	}
}

// browser routes keep their admission and login implementation in browserAccess.
func (h *feedbackHTTP) browserEndpoint(response http.ResponseWriter, request *http.Request) {
	if h.runtime.browser == nil {
		http.NotFound(response, request)
		return
	}
	h.runtime.browser.handle(response, request)
}

func (h *feedbackHTTP) GetBrowserSession(response http.ResponseWriter, request *http.Request) {
	h.browserEndpoint(response, request)
}
func (h *feedbackHTTP) BeginBrowserSignIn(response http.ResponseWriter, request *http.Request, _ publisherv1.BeginBrowserSignInParams) {
	h.browserEndpoint(response, request)
}
func (h *feedbackHTTP) EndBrowserSignIn(response http.ResponseWriter, request *http.Request) {
	h.browserEndpoint(response, request)
}
func (h *feedbackHTTP) SwitchBrowserAccount(response http.ResponseWriter, request *http.Request, _ publisherv1.SwitchBrowserAccountParams) {
	h.browserEndpoint(response, request)
}

func feedbackHTTPAccess(response http.ResponseWriter, request *http.Request) (controlv1.FeedbackReviewerAccess, bool) {
	access, ok := request.Context().Value(feedbackAccessContextKey{}).(controlv1.FeedbackReviewerAccess)
	if !ok {
		http.Error(response, "feedback requires current preview access", http.StatusForbidden)
	}
	return access, ok
}

func (h *feedbackHTTP) ListBrowserFeedback(response http.ResponseWriter, request *http.Request, params publisherv1.ListBrowserFeedbackParams) {
	if access, ok := feedbackHTTPAccess(response, request); ok {
		h.runtime.list(response, request, access, params)
	}
}

func (h *feedbackHTTP) CreateBrowserFeedbackReport(response http.ResponseWriter, request *http.Request, _ publisherv1.CreateBrowserFeedbackReportParams) {
	if access, ok := feedbackHTTPAccess(response, request); ok {
		h.runtime.create(response, request, access)
	}
}

func (h *feedbackHTTP) GetBrowserFeedbackEvidence(response http.ResponseWriter, request *http.Request) {
	httpjson.Write(response, http.StatusOK, publisherv1.BrowserFeedbackEvidence{SchemaVersion: 1, FailedRequests: h.runtime.evidenceForBrowser(request)})
}

func feedbackHTTPID(response http.ResponseWriter, request *http.Request, id string) bool {
	if !opaqueid.Valid(id, opaqueid.FeedbackPrefix) {
		http.NotFound(response, request)
		return false
	}
	return true
}

func (h *feedbackHTTP) GetBrowserFeedbackThread(response http.ResponseWriter, request *http.Request, id publisherv1.FeedbackID) {
	if access, ok := feedbackHTTPAccess(response, request); ok && feedbackHTTPID(response, request, id) {
		h.runtime.read(response, request, id, access)
	}
}

func (h *feedbackHTTP) ListBrowserFeedbackEvents(response http.ResponseWriter, request *http.Request, id publisherv1.FeedbackID, params publisherv1.ListBrowserFeedbackEventsParams) {
	if access, ok := feedbackHTTPAccess(response, request); ok && feedbackHTTPID(response, request, id) {
		h.runtime.events(response, request, id, access, params.AfterCursor)
	}
}

func (h *feedbackHTTP) AppendBrowserFeedbackEvent(response http.ResponseWriter, request *http.Request, id publisherv1.FeedbackID, _ publisherv1.AppendBrowserFeedbackEventParams) {
	if access, ok := feedbackHTTPAccess(response, request); ok && feedbackHTTPID(response, request, id) {
		h.runtime.reply(response, request, id, access)
	}
}
