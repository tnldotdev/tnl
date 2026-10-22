package controlapi

import (
	"context"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) GetProjectPrivateService(w http.ResponseWriter, r *http.Request, project string, service controlv1.PrivateServiceName, params controlv1.GetProjectPrivateServiceParams) {
	w.Header().Set("Cache-Control", "no-store")
	principal, ok := h.authorizeRouteReads(w, r)
	if !ok {
		return
	}
	store, ok := h.store.(interface {
		GetProjectPrivateService(context.Context, controlstate.GetProjectPrivateServiceRequest) (controlstate.PrivateServiceRecord, error)
	})
	if !ok {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "applied service lookup is unavailable")
		return
	}
	record, err := store.GetProjectPrivateService(r.Context(), controlstate.GetProjectPrivateServiceRequest{TeamID: params.TeamId, ProjectKey: project, SourceFingerprint: params.SourceFingerprint, Service: service, IdentityID: principal.identityID, Now: time.Now()})
	if err != nil {
		privateVisitorError(w, "read applied private service", err)
		return
	}
	result := privateRecord(record)
	result.TargetTls = nil
	writeJSON(w, http.StatusOK, result)
}
