package public

import (
	"net/http"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (h *handler) AuthorizeImplementerFeedback(w http.ResponseWriter, r *http.Request) {
	var body controlv1.AuthorizeImplementerFeedbackRequest
	if decodeJSON(w, r, &body) != nil || !body.Operation.Valid() || body.Operation == "report" {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid feedback authorization")
		return
	}
	principal, ok := h.authorizeReads(w, r)
	if !ok {
		return
	}
	if h.feedback == nil {
		writeProblem(w, 503, controlv1.Unavailable, "feedback authorization is unavailable")
		return
	}
	decision, err := h.feedback.AuthorizeImplementerFeedback(r.Context(), principal.identityID, body.ServiceId, body.PreviewId, string(body.Operation), time.Now())
	if err != nil {
		writeFeedbackProblem(r.Context(), w, "authorize implementer feedback", err)
		return
	}
	writeJSON(w, 200, decision)
}
