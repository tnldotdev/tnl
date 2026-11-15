package public

import (
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/control/api/serviceaccess"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (h *handler) SetServiceEnabled(w http.ResponseWriter, r *http.Request, id controlv1.ServiceID) {
	w.Header().Set("Cache-Control", "no-store")
	var body controlv1.SetServiceEnabledRequest
	if decodeJSON(w, r, &body) != nil || body.Enabled == nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "send enabled as true or false")
		return
	}
	store, identity, ok := h.serviceVisitor(w, r)
	if !ok {
		return
	}
	record, err := store.SetServiceEnabled(r.Context(), id, identity, *body.Enabled, time.Now())
	if err != nil {
		serviceVisitorError(r.Context(), w, "change service availability", err)
		return
	}
	writeJSON(w, http.StatusOK, serviceaccess.Service(record))
}
