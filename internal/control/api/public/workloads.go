package public

import (
	"context"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type WorkloadVisitorStore interface {
	ListWorkloadServices(context.Context, string, time.Time) ([]controlstate.WorkloadService, error)
	CheckWorkloadService(context.Context, string, string, time.Time) (controlstate.WorkloadServiceAuthorization, error)
	CreateWorkloadIngressAssignments(context.Context, string, string, string, time.Time) (controlstate.WorkloadIngressAssignments, error)
	CreateWorkloadIngressAssignmentSet(context.Context, string, string, string, int, string, time.Time, ...string) (controlstate.WorkloadIngressAssignments, error)
	SelectWorkloadServiceRun(context.Context, string, string, time.Time) (controlstate.ServiceSelection, error)
	GetWorkloadIngressTransportTrust(context.Context, string, string, time.Time) (controlstate.IngressTransportTrust, error)
	ReleaseWorkloadIngressAssignment(context.Context, string, string, time.Time) error
}

func (h *handler) workloadVisitor(w http.ResponseWriter, r *http.Request) (WorkloadVisitorStore, string, bool) {
	w.Header().Set("Cache-Control", "no-store")
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return nil, "", false
	}
	store, ok := h.store.(WorkloadVisitorStore)
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "workload visitor access is unavailable")
		return nil, "", false
	}
	return store, token, true
}
func workloadVisitorProblem(w http.ResponseWriter, err error) {
	if errors.Is(err, controlstate.ErrServiceConflict) {
		writeProblem(w, 409, controlv1.Conflict, "workload ingress assignment is no longer claimable; request fresh assignments")
		return
	}
	if errors.Is(err, controlstate.ErrCertificateIssuanceInvalid) {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid workload certificate signing request")
		return
	}
	if errors.Is(err, controlstate.ErrWorkloadDenied) || errors.Is(err, controlstate.ErrServiceAccess) {
		writeProblem(w, 403, controlv1.Forbidden, "workload session does not currently authorize this service")
		return
	}
	if errors.Is(err, controlstate.ErrWorkloadConflict) {
		writeProblem(w, 409, controlv1.Conflict, "workload request key belongs to another service")
		return
	}
	serviceVisitorError(w, "authorize workload visitor", err)
}
func (h *handler) ListWorkloadServices(w http.ResponseWriter, r *http.Request) {
	store, token, ok := h.workloadVisitor(w, r)
	if !ok {
		return
	}
	services, err := store.ListWorkloadServices(r.Context(), token, time.Now())
	if err != nil {
		workloadVisitorProblem(w, err)
		return
	}
	writeJSON(w, 200, struct {
		Services []controlstate.WorkloadService `json:"services"`
	}{services})
}
func (h *handler) CheckWorkloadService(w http.ResponseWriter, r *http.Request, service string) {
	store, token, ok := h.workloadVisitor(w, r)
	if !ok {
		return
	}
	result, err := store.CheckWorkloadService(r.Context(), token, service, time.Now())
	if err != nil {
		workloadVisitorProblem(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (h *handler) CreateWorkloadIngressAssignments(w http.ResponseWriter, r *http.Request, service string) {
	store, token, ok := h.workloadVisitor(w, r)
	if !ok {
		return
	}
	var body controlv1.CreateWorkloadIngressAssignmentsJSONRequestBody
	if decodeJSONLimited(w, r, &body, 4096) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid workload ingress assignment request")
		return
	}
	preferences, err := normalizedLocationPreferences(body.PreferredRegions)
	if err != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid preferred regions")
		return
	}
	count := 2
	if body.Count != nil {
		count = *body.Count
	}
	result, err := store.CreateWorkloadIngressAssignmentSet(r.Context(), token, service, body.IdempotencyKey, count, optionalFeedbackString(body.ExcludeIngressId), time.Now(), preferences...)
	if err != nil {
		workloadVisitorProblem(w, err)
		return
	}
	writeJSON(w, 200, result)
}

func privateSelectionResponse(selected controlstate.ServiceSelection) controlv1.ServiceSelection {
	result := controlv1.ServiceSelection{ServiceId: selected.ServiceID, ServiceRunId: selected.ServiceRunID, RunNumber: selected.RunNumber,
		Subject: visitorsubject.Wire(selected.Subject), ExpiresAt: selected.ExpiresAt,
		Protocol: controlv1.ServiceProtocol(selected.Protocol), TrustRevision: selected.TrustRevision, Endpoint: endpointResponse(selected.Endpoint)}
	if selected.PairReady != nil {
		result.PairReady = &controlv1.NativePeerPairReady{PublisherIdentityId: selected.PairReady.PublisherIdentityID, Relays: nativePairRelays(selected.PairReady.Relays)}
	}
	return result
}

func (h *handler) SelectWorkloadServiceRun(w http.ResponseWriter, r *http.Request, service string) {
	store, token, ok := h.workloadVisitor(w, r)
	if !ok {
		return
	}
	result, err := store.SelectWorkloadServiceRun(r.Context(), token, service, time.Now())
	if err != nil {
		workloadVisitorProblem(w, err)
		return
	}
	writeJSON(w, 200, privateSelectionResponse(result))
}

func (h *handler) GetWorkloadIngressTransportTrust(w http.ResponseWriter, r *http.Request, session string) {
	store, token, ok := h.workloadVisitor(w, r)
	if !ok {
		return
	}
	result, err := store.GetWorkloadIngressTransportTrust(r.Context(), token, session, time.Now())
	if err != nil {
		workloadVisitorProblem(w, err)
		return
	}
	writeJSON(w, 200, ingressTransportTrustResponse(result))
}

func (h *handler) ReleaseWorkloadIngressAssignment(w http.ResponseWriter, r *http.Request, session string) {
	store, token, ok := h.workloadVisitor(w, r)
	if !ok {
		return
	}
	if err := store.ReleaseWorkloadIngressAssignment(r.Context(), token, session, time.Now()); err != nil {
		workloadVisitorProblem(w, err)
		return
	}
	w.WriteHeader(204)
}
