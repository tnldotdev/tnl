package public

import (
	"context"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/httpprotection"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type httpProtectionStore interface {
	ReportHTTPProtectionRejections(context.Context, visitorscope.Scope, string, int64, string, httpprotection.Rejections, time.Time) error
}

// mitigation reports have their own small process-wide gate before decoding or
// database access; they cannot queue behind cluster lease work.
var httpProtectionReports = make(chan struct{}, 4)

func admitHTTPProtection(w http.ResponseWriter, r *http.Request) (context.Context, func(), bool) {
	w.Header().Set("Cache-Control", "no-store")
	select {
	case httpProtectionReports <- struct{}{}:
	default:
		w.Header().Set("Retry-After", "1")
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "HTTP protection preparation is busy")
		return nil, nil, false
	}
	call, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	deadline, _ := call.Deadline()
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(deadline)
	return call, func() { cancel(); _ = controller.SetReadDeadline(time.Time{}); <-httpProtectionReports }, true
}

func (h *handler) ReportHTTPProtectionRejections(w http.ResponseWriter, r *http.Request) {
	call, finish, ok := admitHTTPProtection(w, r)
	if !ok {
		return
	}
	defer finish()
	credential, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	var body controlv1.ReportHTTPProtectionRejectionsRequest
	now := time.Now()
	if decodeJSONLimited(w, r, &body, 8192) != nil || body.RunId == "" || len(body.RunId) > 64 || body.RunNumber < 1 || body.Evidence.Validate(now) != nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid HTTP protection report")
		return
	}
	scope := visitorscope.Scope{Kind: visitorscope.Kind(body.Resource.Kind), ID: body.Resource.Id}
	if !scope.Valid() {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid HTTP protection resource")
		return
	}
	store := h.dependencies.HTTPProtection
	if store == nil {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "HTTP protection reporting is unavailable")
		return
	}
	if err := store.ReportHTTPProtectionRejections(call, scope, body.RunId, body.RunNumber, credential, body.Evidence, now); err != nil {
		switch {
		case errors.Is(err, controlstate.ErrHTTPProtectionCapacity):
			w.Header().Set("Retry-After", "1")
			writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "temporary source block capacity is occupied")
		case errors.Is(err, controlstate.ErrHTTPProtectionDisabled):
			writeProblem(w, http.StatusForbidden, controlv1.Forbidden, "temporary source blocks are not enabled for this run")
		case errors.Is(err, controlstate.ErrVisitorPolicy), errors.Is(err, context.DeadlineExceeded), call.Err() != nil:
			w.Header().Set("Retry-After", "1")
			writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "HTTP protection reporting is unavailable; retry later")
		default:
			writeVisitorTokenProblem(r.Context(), w, err)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
