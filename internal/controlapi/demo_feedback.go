package controlapi

import (
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) CreatePublishRunPreview(response http.ResponseWriter, request *http.Request, runID controlv1.PublishRunID) {
	var body controlv1.PublishRunVersionRequest
	if err := decodeJSON(response, request, &body); err != nil || body.PublishRunNumber < 1 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid demo preview request")
		return
	}
	auth, ok := h.authenticatePublishRunRequest(response, request, runID, uint64(body.PublishRunNumber))
	if !ok {
		return
	}
	if h.feedback == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "feedback is unavailable")
		return
	}
	preview, err := h.feedback.CreatePublishRunPreview(request.Context(), auth, time.Now())
	if err != nil {
		writeControlStateProblem(response, "create demo feedback", err)
		return
	}
	writeJSON(response, http.StatusOK, previewResponse(preview))
}
