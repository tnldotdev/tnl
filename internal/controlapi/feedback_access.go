package controlapi

import (
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) GetFeedbackAccess(response http.ResponseWriter, request *http.Request, runID controlv1.PublishRunID) {
	var body controlv1.FeedbackAccessRequest
	if err := decodeJSON(response, request, &body); err != nil || body.PublishRunNumber < 1 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid feedback access request")
		return
	}
	auth, ok := h.authenticatePublishRunRequest(response, request, runID, uint64(body.PublishRunNumber))
	if !ok {
		return
	}
	if h.feedbackAccess == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "feedback access is unavailable")
		return
	}
	actor, err := feedbackReviewerActor(body.Access)
	if err == nil {
		actor, err = h.feedbackBrowserActor(request, auth, actor)
	}
	if err != nil {
		writeControlStateProblem(response, "verify feedback access", err)
		return
	}
	access, err := h.feedbackAccess.ReviewerFeedbackAccess(request.Context(), auth, body.PreviewId, actor, time.Now())
	if err != nil {
		writeControlStateProblem(response, "read feedback access", err)
		return
	}
	writeJSON(response, http.StatusOK, controlv1.FeedbackAccess{RequireSignIn: access.RequireSignIn})
}
