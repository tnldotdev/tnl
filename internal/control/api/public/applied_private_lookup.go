package public

import (
	"context"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/control/api/serviceaccess"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (h *handler) GetProjectService(w http.ResponseWriter, r *http.Request, project string, service controlv1.ServiceName, params controlv1.GetProjectServiceParams) {
	w.Header().Set("Cache-Control", "no-store")
	principal, ok := h.authorizeRouteReads(w, r)
	if !ok {
		return
	}
	store, ok := h.store.(interface {
		GetProjectService(context.Context, controlstate.GetProjectServiceRequest) (controlstate.ServiceRecord, error)
	})
	if !ok {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "applied service lookup is unavailable")
		return
	}
	record, err := store.GetProjectService(r.Context(), controlstate.GetProjectServiceRequest{TeamID: params.TeamId, ProjectKey: project, SourceFingerprint: params.SourceFingerprint, Service: service, IdentityID: principal.identityID, Now: time.Now()})
	if err != nil {
		privateVisitorError(w, "read applied service", err)
		return
	}
	result := serviceaccess.Service(record)
	result.TargetTls = nil
	writeJSON(w, http.StatusOK, result)
}
