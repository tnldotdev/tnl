package authority

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/control/oidc"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type WorkloadApprovalStore interface {
	AuthenticateEnvironmentPublisherManager(context.Context, credentials.AccessToken) (controlstate.EnvironmentPublisherManager, error)
	GetWorkloadApproval(context.Context, string, string, controlstate.EnvironmentPublisherManager) (controlstate.WorkloadApproval, error)
	ApproveWorkload(context.Context, string, string, controlstate.EnvironmentPublisherManager, controlstate.WorkloadApprovalRequest, time.Time) (controlstate.WorkloadApproval, error)
}

func (h *handler) GetWorkloadApproval(w http.ResponseWriter, r *http.Request, team, intent string) {
	s, manager, ok := h.workloadApprovalManager(w, r)
	if !ok {
		return
	}
	result, err := s.GetWorkloadApproval(r.Context(), team, intent, manager)
	if err != nil {
		workloadApprovalProblem(r.Context(), w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.workloadApprovalResponse(result))
}

func (h *handler) ApproveWorkload(w http.ResponseWriter, r *http.Request, team, intent string) {
	s, manager, ok := h.workloadApprovalManager(w, r)
	if !ok {
		return
	}
	var body authorityv1.WorkloadApprovalRequest
	if decodeEnvironmentVisitorJSON(w, r, &body, "project_key", "environment_id", "expected_revision", "workload", "intent_hash", "trust", "services", "max_duration_seconds", "expires_at") != nil {
		machineProblem(r.Context(), w, controlstate.ErrEnvironmentInvalid)
		return
	}
	trust := oidc.WorkloadTrust{Provider: string(body.Trust.Provider), Issuer: body.Trust.Issuer, JWKSURL: body.Trust.JwksUrl, Audience: body.Trust.Audience, Claims: body.Trust.Claims}
	if body.Trust.Events != nil {
		trust.Events = *body.Trust.Events
	}
	request := controlstate.WorkloadApprovalRequest{ProjectKey: body.ProjectKey, EnvironmentID: body.EnvironmentId, ExpectedRevision: body.ExpectedRevision, Workload: body.Workload, IntentHash: body.IntentHash, Trust: trust, Services: body.Services, MaxDurationSeconds: body.MaxDurationSeconds, ExpiresAt: body.ExpiresAt}
	result, err := s.ApproveWorkload(r.Context(), team, intent, manager, request, time.Now())
	if err != nil {
		workloadApprovalProblem(r.Context(), w, err)
		return
	}
	writeJSON(w, http.StatusOK, h.workloadApprovalResponse(result))
}

func workloadApprovalProblem(ctx context.Context, w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, controlstate.ErrControlAuthentication):
		writeBearerProblem(w)
	case errors.Is(err, controlstate.ErrWorkloadApprovalNotFound):
		writeProblem(w, 404, authorityv1.NotFound, "workload approval intent not found")
	case errors.Is(err, controlstate.ErrWorkloadApprovalConflict), errors.Is(err, controlstate.ErrEnvironmentStale):
		writeProblem(w, 409, authorityv1.Conflict, "approval intent differs or environment revision changed; inspect the original intent or use a new explicit intent")
	default:
		machineProblem(ctx, w, err)
	}
}

func (h *handler) workloadApprovalManager(w http.ResponseWriter, r *http.Request) (MachineStore, controlstate.EnvironmentPublisherManager, bool) {
	s, ok := h.machineStore(w)
	if !ok {
		return nil, controlstate.EnvironmentPublisherManager{}, false
	}
	token, err := credentials.Bearer(r.Header)
	if err != nil {
		writeBearerProblem(w)
		return nil, controlstate.EnvironmentPublisherManager{}, false
	}
	manager, err := s.AuthenticateEnvironmentPublisherManager(r.Context(), credentials.AccessToken(token))
	if err != nil {
		workloadApprovalProblem(r.Context(), w, err)
		return nil, controlstate.EnvironmentPublisherManager{}, false
	}
	return s, manager, true
}

func machineTrustResponse(trust oidc.WorkloadTrust) authorityv1.MachineTrust {
	result := authorityv1.MachineTrust{Provider: authorityv1.MachineTrustProvider(trust.Provider), Issuer: trust.Issuer, JwksUrl: trust.JWKSURL, Audience: trust.Audience, Claims: trust.Claims}
	if trust.Events != nil {
		result.Events = &trust.Events
	}
	return result
}

func (h *handler) workloadApprovalResponse(a controlstate.WorkloadApproval) authorityv1.WorkloadApproval {
	r := a.Request
	request := authorityv1.WorkloadApprovalRequest{ProjectKey: r.ProjectKey, EnvironmentId: r.EnvironmentID, ExpectedRevision: r.ExpectedRevision, Workload: r.Workload, IntentHash: r.IntentHash, Trust: machineTrustResponse(r.Trust), Services: r.Services, MaxDurationSeconds: r.MaxDurationSeconds, ExpiresAt: r.ExpiresAt}
	protocols := make(map[string]controlv1.ServiceProtocol, len(a.Protocols))
	for name, protocol := range a.Protocols {
		protocols[name] = controlv1.ServiceProtocol(protocol)
	}
	machine := authorityv1.MachineIdentity{Id: a.Machine.ID, TeamId: a.Machine.TeamID, Name: a.Machine.Name, ProofKind: authorityv1.MachineIdentityProofKind(a.Machine.ProofKind), Trust: new(machineTrustResponse(a.Machine.Trust)), Revision: a.Machine.Revision}
	selection := authorityv1.IdentitySourceVisitorSelection{Environment: controlv1.EnvironmentReference{Server: h.config.ControlURL, ProjectKey: r.ProjectKey, EnvironmentId: r.EnvironmentID}, PermissionId: a.PermissionID, Services: protocols}
	return authorityv1.WorkloadApproval{IntentKey: a.IntentKey, Request: request, Machine: machine, Selection: selection, MachineRevokedAt: a.MachineRevokedAt, PermissionRevokedAt: a.PermissionRevokedAt, CreatedAt: a.CreatedAt}
}
