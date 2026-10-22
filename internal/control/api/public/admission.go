package public

import (
	"net/http"

	"github.com/tnldotdev/tnl/internal/observability"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// existing run renewals and cleanup remain available during process drain.
// new assignment/run creation checks the local process gate before state work.
func (h *handler) acceptingNewWork(w http.ResponseWriter) bool {
	if h.config.AcceptingNewWork != nil && !h.config.AcceptingNewWork() {
		observability.DrainingRequest(observability.ResponseContext(w))
		w.Header().Set("Retry-After", "1")
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "control is draining; retry another control process")
		return false
	}
	return true
}
