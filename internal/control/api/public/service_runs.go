package public

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/region"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type serviceRunStore interface {
	PrepareServiceRun(context.Context, string, controlstate.PublisherIdentity, string, time.Time, controlstate.ServiceRunRequest) (controlstate.ServiceRunPreparation, error)
	HeartbeatServiceRun(context.Context, string, string, string, time.Time, controlstate.ServiceRunHealth) (controlstate.ServiceRunState, error)
	CloseServiceRun(context.Context, string, string, string, time.Time) error
}

func (h *handler) serviceRuns(w http.ResponseWriter) (serviceRunStore, bool) {
	store, ok := h.dependencies.ServiceRuns, h.dependencies.ServiceRuns != nil
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "service runs are unavailable")
	}
	return store, ok
}

func serviceRunProblem(ctx context.Context, w http.ResponseWriter, operation string, err error) {
	if errors.Is(err, region.ErrPreference) {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, region.ErrPreference.Error())
		return
	}
	if errors.Is(err, controlstate.ErrInsufficientRelayServices) {
		writeProblem(w, 503, controlv1.Unavailable, "two live relay services are required")
		return
	}
	serviceVisitorError(ctx, w, operation, err)
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
	if !h.acceptingNewWork(r.Context(), w) {
		return
	}
	var body controlv1.ServiceRunDeclaration
	var raw json.RawMessage
	if decodeJSONLimited(w, r, &raw, 2<<20) != nil ||
		httpjson.Decode(json.NewDecoder(bytes.NewReader(raw)), &body) != nil || trafficHasNull(raw) || body.TrustRevision < 1 {
		writeProblem(w, 400, controlv1.InvalidRequest, "declare the service protocol and TLS trust revision")
		return
	}
	declaration := controlstate.ServiceMetadata{Protocol: string(body.Protocol), TLS: targetTLSInput(body.TargetTls), TrustRevision: body.TrustRevision}
	if declaration.Validate() != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid service protocol or TLS trust")
		return
	}
	traffic := trafficSelection(body.Traffic)
	if traffic != nil && traffic.Validate() != nil {
		writeControlStateProblem(r.Context(), w, "select service-run traffic limits", controlstate.ErrTrafficSelection)
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
	var preferences []string
	if body.PreferredRegions != nil {
		preferences = *body.PreferredRegions
	}
	prepared, err := store.PrepareServiceRun(r.Context(), serviceID, publisher, r.Header.Get("Idempotency-Key"), time.Now(), controlstate.ServiceRunRequest{
		Metadata: declaration, PreferredRegions: preferences, TrafficSelection: traffic,
		TrafficDefaults: h.config.TrafficDefaults, TrafficCeiling: h.config.TrafficCeiling,
	})
	if err != nil {
		serviceRunProblem(r.Context(), w, "prepare service run", err)
		return
	}
	approval := trafficLimitsResponse(prepared.Traffic)
	if approval == nil || prepared.Traffic.RatePer == 0 {
		serviceRunProblem(r.Context(), w, "read service-run traffic approval", errors.New("invalid stored traffic approval"))
		return
	}
	response := controlv1.ServiceRunPreparation{
		TeamId: prepared.TeamID, ServiceId: prepared.ServiceID,
		ServiceRunId: prepared.RunID, RunNumber: prepared.RunNumber,
		PublisherIdentityId: prepared.PublisherIdentityID, PublisherGrantId: prepared.PublisherGrantID,
		PublisherKeyId: prepared.PublisherKeyID, IdempotencyKey: prepared.IdempotencyKey,
		ExpiresAt: prepared.ExpiresAt,
		Hostname:  prepared.Hostname, DomainId: prepared.DomainID,
		Traffic: *approval,
	}
	if len(prepared.CertificatePlan.Identifiers) != 0 {
		plan := managedCertificatePlan(prepared.CertificatePlan)
		response.CertificatePlan = &plan
	}
	writeJSON(w, http.StatusCreated, response)
}

func (h *handler) StartServiceRun(w http.ResponseWriter, r *http.Request, service controlv1.ServiceID, run controlv1.ServiceRunID) {
	if !h.acceptingNewWork(r.Context(), w) {
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
	store, ok := h.dependencies.ServiceRuns, h.dependencies.ServiceRuns != nil
	if !ok {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "service runs are unavailable")
		return
	}
	state, err := store.StartServiceRun(r.Context(), service, run, body.RunNumber, publisher, time.Now())
	if err != nil {
		serviceRunProblem(r.Context(), w, "start service run", err)
		return
	}
	writeJSON(w, http.StatusOK, controlv1.ServiceRunSetup{ServiceId: state.ServiceID, ServiceRunId: state.RunID, RunNumber: state.RunNumber, RunToken: state.Token, PublisherConnections: serviceRunConnections(state.Connections)})
}

func (h *handler) RenewServiceRun(w http.ResponseWriter, r *http.Request, serviceID controlv1.ServiceID, runID controlv1.ServiceRunID) {
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
		serviceRunProblem(r.Context(), w, "heartbeat service run", err)
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
		serviceRunProblem(r.Context(), w, "close service run", err)
		return
	}
	w.WriteHeader(204)
}
