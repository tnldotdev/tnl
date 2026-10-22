package controlapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type serviceAuditStore interface {
	ListServiceAudit(context.Context, string, string, controlstate.ServiceAuditFilter, time.Time) (controlstate.ServiceAuditPage, error)
	IngestPublisherServiceObservations(context.Context, controlstate.PublishRunAuthentication, serviceaudit.Batch, time.Time) (controlstate.ServiceObservationResult, error)
}

func serviceAuditError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, serviceaudit.ErrInvalid):
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid service audit request")
	case errors.Is(err, controlstate.ErrServiceAuditAccess):
		writeProblem(w, 403, controlv1.Forbidden, "service audit access denied")
	default:
		writeControlStateProblem(w, "service audit", err)
	}
}

func (h *handler) ListServiceAudit(w http.ResponseWriter, r *http.Request, team string, p controlv1.ListServiceAuditParams) {
	principal, ok := h.authorizeRouteReads(w, r)
	if !ok {
		return
	}
	store, ok := h.store.(serviceAuditStore)
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "service audit is unavailable")
		return
	}
	f := controlstate.ServiceAuditFilter{Since: p.Since}
	if p.ServiceId != nil {
		f.ServiceID = *p.ServiceId
	}
	if p.Service != nil {
		f.Service = *p.Service
	}
	if p.After != nil {
		f.After = fmt.Sprint(*p.After)
	}
	if p.Limit != nil {
		f.Limit = *p.Limit
		if f.Limit < 1 {
			serviceAuditError(w, serviceaudit.ErrInvalid)
			return
		}
	}
	page, err := store.ListServiceAudit(r.Context(), team, principal.identityID, f, time.Now().UTC())
	if err != nil {
		serviceAuditError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, page)
}

func (h *handler) ReportPublishRunServiceObservations(w http.ResponseWriter, r *http.Request, runID string) {
	var body struct {
		PublishRunNumber int64                      `json:"publish_run_number"`
		Events           []serviceaudit.Observation `json:"events"`
	}
	if decodeJSONLimited(w, r, &body, serviceaudit.MaxPayloadBytes) != nil || body.PublishRunNumber < 1 {
		serviceAuditError(w, serviceaudit.ErrInvalid)
		return
	}
	auth, ok := h.authenticatePublishRunRequest(w, r, runID, uint64(body.PublishRunNumber))
	if !ok {
		return
	}
	store, ok := h.store.(serviceAuditStore)
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "service audit is unavailable")
		return
	}
	for i := range body.Events {
		if body.Events[i].RunNumber == 0 {
			body.Events[i].RunNumber = body.PublishRunNumber
		}
		if body.Events[i].ConnectorSessionID != "" {
			serviceAuditError(w, serviceaudit.ErrInvalid)
			return
		}
	}
	result, err := store.IngestPublisherServiceObservations(r.Context(), auth, serviceaudit.Batch{Events: body.Events}, time.Now().UTC())
	if err != nil {
		serviceAuditError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
