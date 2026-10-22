package controlapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type privateRunStore interface {
	PreparePrivateServiceRun(context.Context, string, controlstate.PublisherIdentity, string, time.Time, ...controlstate.PrivateServiceMetadata) (controlstate.PrivateRunPreparation, error)
	HeartbeatPrivateServiceRun(context.Context, string, string, string, time.Time, ...controlstate.PrivateRunHealth) (controlstate.PrivateRunState, error)
	ClosePrivateServiceRun(context.Context, string, string, string, time.Time) error
}

func (h *handler) privateRuns(w http.ResponseWriter) (privateRunStore, bool) {
	store, ok := h.store.(privateRunStore)
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "private service runs are unavailable")
	}
	return store, ok
}

func privateRunProblem(w http.ResponseWriter, operation string, err error) {
	if errors.Is(err, controlstate.ErrInsufficientRelayServices) {
		writeProblem(w, 503, controlv1.Unavailable, "two live relay services are required")
		return
	}
	privateVisitorError(w, operation, err)
}

func privateRunConnections(rows []controlstate.PrivateRunAssignment) []controlv1.ConnectionAssignment {
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

func (h *handler) PreparePrivateServiceRun(w http.ResponseWriter, r *http.Request, serviceID controlv1.PrivateServiceID, _ controlv1.PreparePrivateServiceRunParams) {
	if !h.acceptingNewWork(w) {
		return
	}
	var body controlv1.PrivateServiceRunDeclaration
	if decodeJSONLimited(w, r, &body, 2<<20) != nil || body.TrustRevision < 1 {
		writeProblem(w, 400, controlv1.InvalidRequest, "declare the private service protocol and TLS trust revision")
		return
	}
	declaration := controlstate.PrivateServiceMetadata{Protocol: string(body.Protocol), TLS: privateTLSInput(body.TargetTls), TrustRevision: body.TrustRevision}
	if declaration.Validate() != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid private service protocol or TLS trust")
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
	store, ok := h.privateRuns(w)
	if !ok {
		return
	}
	prepared, err := store.PreparePrivateServiceRun(r.Context(), serviceID, publisher, r.Header.Get("Idempotency-Key"), time.Now(), declaration)
	if err != nil {
		privateRunProblem(w, "prepare private service run", err)
		return
	}
	response := controlv1.PrivateServiceRunPreparation{
		TeamId: prepared.TeamID, PrivateServiceId: prepared.ServiceID,
		PrivateRunId: prepared.RunID, RunNumber: prepared.RunNumber,
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

func (h *handler) StartManagedServiceRun(w http.ResponseWriter, r *http.Request, service controlv1.PrivateServiceID, run controlv1.PrivateRunID) {
	if !h.acceptingNewWork(w) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var body controlv1.StartManagedServiceRunJSONRequestBody
	if decodeJSON(w, r, &body) != nil || body.RunNumber < 1 {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid managed service run")
		return
	}
	_, publisher, ok := h.authenticatePublisher(w, r)
	if !ok {
		return
	}
	store, ok := h.store.(interface {
		StartManagedServiceRun(context.Context, string, string, int64, controlstate.PublisherIdentity, time.Time) (controlstate.PrivateRunState, error)
	})
	if !ok {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "managed service runs are unavailable")
		return
	}
	state, err := store.StartManagedServiceRun(r.Context(), service, run, body.RunNumber, publisher, time.Now())
	if err != nil {
		privateRunProblem(w, "start managed service run", err)
		return
	}
	writeJSON(w, http.StatusOK, controlv1.PrivateServiceRunSetup{PrivateServiceId: state.ServiceID, PrivateRunId: state.RunID, RunNumber: state.RunNumber, RunToken: state.Token, PublisherConnections: privateRunConnections(state.Connections)})
}

func (h *handler) HeartbeatPrivateServiceRun(w http.ResponseWriter, r *http.Request, serviceID controlv1.PrivateServiceID, runID controlv1.PrivateRunID) {
	var body controlv1.PrivateServiceRunHeartbeat
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "report the private publisher health and stream capacity")
		return
	}
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	store, ok := h.privateRuns(w)
	if !ok {
		return
	}
	state, err := store.HeartbeatPrivateServiceRun(r.Context(), serviceID, runID, token, time.Now(), controlstate.PrivateRunHealth{Healthy: body.Healthy, StreamCapacity: body.StreamCapacity, ActiveStreams: body.ActiveStreams})
	if err != nil {
		privateRunProblem(w, "heartbeat private service run", err)
		return
	}
	writeJSON(w, 200, controlv1.PrivateServiceRunState{
		PrivateServiceId: state.ServiceID, PrivateRunId: state.RunID, RunNumber: state.RunNumber,
		State: controlv1.PrivateServiceRunStateState(state.State), PublisherExpiresAt: state.ExpiresAt,
		Healthy: &state.Healthy, StreamCapacity: &state.StreamCapacity, ActiveStreams: &state.ReportedStreams,
		PublisherConnections: privateRunConnections(state.Connections),
	})
}

func (h *handler) ClosePrivateServiceRun(w http.ResponseWriter, r *http.Request, serviceID controlv1.PrivateServiceID, runID controlv1.PrivateRunID) {
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	store, ok := h.privateRuns(w)
	if !ok {
		return
	}
	if err := store.ClosePrivateServiceRun(r.Context(), serviceID, runID, token, time.Now()); err != nil {
		privateRunProblem(w, "close private service run", err)
		return
	}
	w.WriteHeader(204)
}
