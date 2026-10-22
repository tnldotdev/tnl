package controlapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type WorkloadVisitorStore interface {
	ListWorkloadServices(context.Context, string, time.Time) ([]controlstate.WorkloadService, error)
	CheckWorkloadService(context.Context, string, string, time.Time) (controlstate.WorkloadServiceAuthorization, error)
	CreateWorkloadIngressAssignments(context.Context, string, string, string, time.Time) (controlstate.WorkloadIngressAssignments, error)
	IssueWorkloadServiceClientCertificate(context.Context, string, string, []byte, time.Time) (controlstate.ServiceClientCertificate, error)
	CreateWorkloadIngressAssignmentSet(context.Context, string, string, string, int, string, time.Time) (controlstate.WorkloadIngressAssignments, error)
	SelectWorkloadServiceRun(context.Context, string, string, time.Time) (controlstate.PrivateServiceSelection, error)
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
	if errors.Is(err, controlstate.ErrPrivateServiceConflict) {
		writeProblem(w, 409, controlv1.Conflict, "workload ingress assignment is no longer claimable; request fresh assignments")
		return
	}
	if errors.Is(err, controlstate.ErrCertificateIssuanceInvalid) {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid workload certificate signing request")
		return
	}
	if errors.Is(err, controlstate.ErrWorkloadDenied) || errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		writeProblem(w, 403, controlv1.Forbidden, "workload session does not currently authorize this service")
		return
	}
	if errors.Is(err, controlstate.ErrWorkloadConflict) {
		writeProblem(w, 409, controlv1.Conflict, "workload request key belongs to another service")
		return
	}
	privateVisitorError(w, "authorize workload visitor", err)
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
	count := 2
	if body.Count != nil {
		count = *body.Count
	}
	result, err := store.CreateWorkloadIngressAssignmentSet(r.Context(), token, service, body.IdempotencyKey, count, optionalFeedbackString(body.ExcludeIngressId), time.Now())
	if err != nil {
		workloadVisitorProblem(w, err)
		return
	}
	writeJSON(w, 200, result)
}

func privateSelectionResponse(selected controlstate.PrivateServiceSelection) controlv1.PrivateServiceSelection {
	return controlv1.PrivateServiceSelection{PrivateServiceId: selected.PrivateServiceID, PrivateRunId: selected.PrivateRunID, RunNumber: selected.RunNumber,
		Subject: visitorsubject.Wire(selected.Subject), ExpiresAt: selected.ExpiresAt,
		Protocol: controlv1.PrivateServiceProtocol(selected.Protocol), TrustRevision: selected.TrustRevision, ManagedTls: managedTLSResponse(selected.ManagedTLS)}
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
func (h *handler) IssueWorkloadServiceClientCertificate(w http.ResponseWriter, r *http.Request, service string) {
	store, token, ok := h.workloadVisitor(w, r)
	if !ok {
		return
	}
	var body struct {
		CSR []byte `json:"csr"`
	}
	if decodeJSONLimited(w, r, &body, 16<<10) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid workload certificate request")
		return
	}
	result, err := store.IssueWorkloadServiceClientCertificate(r.Context(), token, service, body.CSR, time.Now())
	if err != nil {
		workloadVisitorProblem(w, err)
		return
	}
	writeJSON(w, 200, result)
}
