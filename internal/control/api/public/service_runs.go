package public

import (
	"context"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type serviceRunStore interface {
	PrepareServiceRun(context.Context, string, controlstate.PublisherIdentity, string, time.Time, controlstate.ServiceMetadata) (controlstate.ServiceRunPreparation, error)
	HeartbeatServiceRun(context.Context, string, string, string, time.Time, ...controlstate.ServiceRunHealth) (controlstate.ServiceRunState, error)
	CloseServiceRun(context.Context, string, string, string, time.Time) error
}

func (h *handler) serviceRuns(w http.ResponseWriter) (serviceRunStore, bool) {
	store, ok := h.store.(serviceRunStore)
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "service runs are unavailable")
	}
	return store, ok
}

func serviceRunProblem(w http.ResponseWriter, operation string, err error) {
	if errors.Is(err, controlstate.ErrInsufficientRelayServices) {
		writeProblem(w, 503, controlv1.Unavailable, "two live relay services are required")
		return
	}
	privateVisitorError(w, operation, err)
}

func serviceRunConnections(rows []controlstate.ServiceRunAssignment) []controlv1.ConnectionAssignment {
	result := make([]controlv1.ConnectionAssignment, 0, len(rows))
	for _, row := range rows {
		result = append(result, controlv1.ConnectionAssignment{
			PublisherConnectionId: row.PublisherConnectionID,
			ConnectionSlot:        int(row.ConnectionSlot), ConnectionAssignmentRevision: row.Revision,
			PublisherConnectionCredential:          row.Credential,
			PublisherConnectionCredentialExpiresAt: row.CredentialExpiresAt,
			RelayServiceId:                         row.RelayServiceID, RelayAddress: row.RelayAddress,
			TlsServerName: row.TLSServerName, State: controlv1.PublisherConnectionState(row.State),
		})
	}
	return result
}

func (h *handler) PrepareServiceRun(w http.ResponseWriter, r *http.Request, serviceID controlv1.ServiceID, _ controlv1.PrepareServiceRunParams) {
	if !h.acceptingNewWork(w) {
		return
	}
	var body controlv1.ServiceRunDeclaration
	if decodeJSONLimited(w, r, &body, 2<<20) != nil || body.TrustRevision < 1 {
		writeProblem(w, 400, controlv1.InvalidRequest, "declare the service protocol and TLS trust revision")
		return
	}
	declaration := controlstate.ServiceMetadata{Protocol: string(body.Protocol), TLS: privateTLSInput(body.TargetTls), TrustRevision: body.TrustRevision}
	if declaration.Validate() != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid service protocol or TLS trust")
		return
	}
	if r.Header.Get("Idempotency-Key") == "" {
		writeProblem(w, 400, controlv1.InvalidRequest, "idempotency key is required")
		return
	}
	_, publisher, ok := h.authenticatePublisher(w, r)
	if !ok {
		return
	}
	store, ok := h.serviceRuns(w)
	if !ok {
		return
	}
	prepared, err := store.PrepareServiceRun(r.Context(), serviceID, publisher, r.Header.Get("Idempotency-Key"), time.Now(), declaration)
	if err != nil {
		serviceRunProblem(w, "prepare service run", err)
		return
	}
	response := controlv1.ServiceRunPreparation{
		TeamId: prepared.TeamID, ServiceId: prepared.ServiceID,
		ServiceRunId: prepared.RunID, RunNumber: prepared.RunNumber,
		PublisherIdentityId: prepared.PublisherIdentityID, PublisherGrantId: prepared.PublisherGrantID,
		PublisherKeyId: prepared.PublisherKeyID, IdempotencyKey: prepared.IdempotencyKey,
		ExpiresAt: prepared.ExpiresAt,
		Hostname:  prepared.Hostname, ServicePort: prepared.ServicePort, DomainId: prepared.DomainID,
	}
	if len(prepared.CertificatePlan.Identifiers) != 0 {
		plan := managedCertificatePlan(prepared.CertificatePlan)
		response.CertificatePlan = &plan
	}
	writeJSON(w, http.StatusCreated, response)
}

func (h *handler) StartServiceRun(w http.ResponseWriter, r *http.Request, service controlv1.ServiceID, run controlv1.ServiceRunID) {
	if !h.acceptingNewWork(w) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var body controlv1.StartServiceRunJSONRequestBody
	if decodeJSON(w, r, &body) != nil || body.RunNumber < 1 {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid service run")
		return
	}
	_, publisher, ok := h.authenticatePublisher(w, r)
	if !ok {
		return
	}
	store, ok := h.store.(interface {
		StartServiceRun(context.Context, string, string, int64, controlstate.PublisherIdentity, time.Time) (controlstate.ServiceRunState, error)
	})
	if !ok {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "service runs are unavailable")
		return
	}
	state, err := store.StartServiceRun(r.Context(), service, run, body.RunNumber, publisher, time.Now())
	if err != nil {
		serviceRunProblem(w, "start service run", err)
		return
	}
	writeJSON(w, http.StatusOK, controlv1.ServiceRunSetup{ServiceId: state.ServiceID, ServiceRunId: state.RunID, RunNumber: state.RunNumber, RunToken: state.Token, PublisherConnections: serviceRunConnections(state.Connections)})
}

func (h *handler) HeartbeatServiceRun(w http.ResponseWriter, r *http.Request, serviceID controlv1.ServiceID, runID controlv1.ServiceRunID) {
	var body controlv1.ServiceRunHeartbeat
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "report the private publisher health and stream capacity")
		return
	}
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	store, ok := h.serviceRuns(w)
	if !ok {
		return
	}
	state, err := store.HeartbeatServiceRun(r.Context(), serviceID, runID, token, time.Now(), controlstate.ServiceRunHealth{Healthy: body.Healthy, StreamCapacity: body.StreamCapacity, ActiveStreams: body.ActiveStreams})
	if err != nil {
		serviceRunProblem(w, "heartbeat service run", err)
		return
	}
	writeJSON(w, 200, controlv1.ServiceRunState{
		ServiceId: state.ServiceID, ServiceRunId: state.RunID, RunNumber: state.RunNumber,
		State: controlv1.ServiceRunStateState(state.State), PublisherExpiresAt: state.ExpiresAt,
		Healthy: &state.Healthy, StreamCapacity: &state.StreamCapacity, ActiveStreams: &state.ReportedStreams,
		PublisherConnections: serviceRunConnections(state.Connections),
	})
}

func (h *handler) CloseServiceRun(w http.ResponseWriter, r *http.Request, serviceID controlv1.ServiceID, runID controlv1.ServiceRunID) {
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	store, ok := h.serviceRuns(w)
	if !ok {
		return
	}
	if err := store.CloseServiceRun(r.Context(), serviceID, runID, token, time.Now()); err != nil {
		serviceRunProblem(w, "close service run", err)
		return
	}
	w.WriteHeader(204)
}
