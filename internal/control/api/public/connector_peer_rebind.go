package public

import (
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// the generated contract precedes durable rebind authority. fail closed until
// that owner implements and wires the lifecycle operation; never select a run.
func (h *handler) RebindConnectorPeerPair(w http.ResponseWriter, _ *http.Request, _ controlv1.ServiceID, _ string) {
	w.Header().Set("Cache-Control", "no-store")
	writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "connector network rebinding is unavailable")
}
