package ingressapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/serviceaudit"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

type serviceAuditStore interface {
	IngestIngressServiceObservations(context.Context, controlstate.IngressLeaseIdentity, serviceaudit.Batch, time.Time) (controlstate.ServiceObservationResult, error)
}

func (s generatedServer) ReportIngressServiceObservations(w http.ResponseWriter, r *http.Request, id ingressv1.IngressID, p ingressv1.ReportIngressServiceObservationsParams) {
	lease, ok := ingressLeaseIdentity(id, p.IngressRunId, p.IngressLeaseRevision)
	if !ok {
		serviceapi.WriteProblem(w, 400, "invalid_request", "invalid ingress lease")
		return
	}
	var batch serviceaudit.Batch
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, serviceaudit.MaxPayloadBytes))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&batch) != nil || decoder.Decode(new(any)) != io.EOF {
		serviceapi.WriteProblem(w, 400, "invalid_request", "invalid service observations")
		return
	}
	result, err := s.handler.service.IngestServiceObservations(r.Context(), lease, batch)
	if errors.Is(err, serviceaudit.ErrInvalid) {
		serviceapi.WriteProblem(w, 400, "invalid_request", "invalid service observations")
		return
	}
	if errors.Is(err, controlstate.ErrServiceAuditAccess) {
		serviceapi.WriteProblem(w, 403, "forbidden", "service observation scope is not current")
		return
	}
	if s.handler.writeServiceError(w, r, err) {
		return
	}
	serviceapi.WriteJSON(w, 200, result)
}

// IngestServiceObservations gives standalone the same lease checks as HTTP.
func (s *service) IngestServiceObservations(ctx context.Context, lease controlstate.IngressLeaseIdentity, batch serviceaudit.Batch) (controlstate.ServiceObservationResult, error) {
	store, ok := s.store.(serviceAuditStore)
	if !ok {
		return controlstate.ServiceObservationResult{}, serviceapi.NewProblemError(503, "unavailable", "service audit is unavailable")
	}
	return store.IngestIngressServiceObservations(ctx, lease, batch, s.now())
}
