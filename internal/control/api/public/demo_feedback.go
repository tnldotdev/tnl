package public

import (
	"net/http"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (h *handler) CreateServiceRunPreview(response http.ResponseWriter, request *http.Request, service controlv1.ServiceID, run controlv1.ServiceRunID) {
	var body controlv1.ServiceRunPreviewRequest
	if decodeJSON(response, request, &body) != nil || body.RunNumber < 1 {
		writeProblem(response, 400, controlv1.InvalidRequest, "invalid demo preview request")
		return
	}
	token, ok := requestBearerToken(request)
	if !ok {
		writeBearerProblem(response)
		return
	}
	if h.feedback == nil {
		writeProblem(response, 503, controlv1.Unavailable, "feedback is unavailable")
		return
	}
	preview, err := h.feedback.CreateServiceRunPreview(request.Context(), serviceHTTPRun(service, run, token, body.RunNumber), time.Now())
	if err != nil {
		writeControlStateProblem(request.Context(), response, "create demo feedback", err)
		return
	}
	writeJSON(response, 200, previewResponse(preview))
}
