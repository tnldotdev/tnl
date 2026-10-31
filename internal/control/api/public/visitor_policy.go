package public

import (
	"context"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type publisherVisitorPolicyStore interface {
	ReadPublisherVisitorPolicy(context.Context, visitorscope.Scope, string, int64, string, int64, time.Time) (controlv1.VisitorPolicyUpdate, error)
}

const maxPublisherVisitorPolicyRequestBytes = 1024

func (h *handler) ReadPublisherVisitorPolicy(w http.ResponseWriter, r *http.Request) {
	observed := time.Now()
	w.Header().Set("Cache-Control", "no-store")
	credential, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	var body controlv1.PublisherVisitorPolicyRequest
	if decodeJSONLimited(w, r, &body, maxPublisherVisitorPolicyRequestBytes) != nil || body.RunId == "" || body.RunNumber < 1 || body.AfterRevision < 0 || utf8.RuneCountInString(body.RunId) > 64 {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid publisher policy request")
		return
	}
	scope := visitorscope.Scope{Kind: visitorscope.Kind(body.Resource.Kind), ID: body.Resource.Id}
	if !scope.Valid() {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid visitor policy resource")
		return
	}
	store, ok := h.store.(publisherVisitorPolicyStore)
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "visitor policy is unavailable")
		return
	}
	result, err := store.ReadPublisherVisitorPolicy(r.Context(), scope, body.RunId, body.RunNumber, credential, body.AfterRevision, observed)
	if err != nil {
		writeVisitorTokenProblem(w, err)
		return
	}
	writeJSON(w, 200, result)
}
