package authority

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/control/oidc"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

type MachineStore interface {
	WorkloadApprovalStore
	RegisterMachineIdentity(context.Context, controlstate.RegisterMachineRequest, time.Time) (controlstate.MachineIdentity, error)
	RotateMachineIdentityKey(context.Context, string, string, string, string, ed25519.PublicKey, time.Time) error
	RevokeMachineIdentity(context.Context, string, string, string, time.Time) error
	MachineIdentityPolicy(context.Context, string) (controlstate.MachineIdentity, error)
	ProvisioningIdentityPolicy(context.Context, string, time.Time) (controlstate.MachineIdentity, error)
	CreateProvisioningGrant(context.Context, controlstate.ProvisioningGrant, string, time.Time) (controlstate.ProvisioningGrant, error)
	RevokeProvisioningGrant(context.Context, string, string, string, time.Time) error
	CreateEnvironmentVisitorPermission(context.Context, controlstate.EnvironmentVisitorPermission, string, time.Time) (controlstate.EnvironmentVisitorPermission, error)
	RevokeEnvironmentVisitorPermission(context.Context, string, string, string, time.Time) error
	ExchangeProvisioning(context.Context, string, string, controlstate.ProvisioningOperation, controlstate.MachineProof, string, time.Time) (controlstate.ProvisioningSession, error)
}

var _ MachineStore = (*controlstate.Database)(nil)

func machineProblem(ctx context.Context, w http.ResponseWriter, err error) {
	if errors.Is(err, controlstate.ErrMachineDenied) || errors.Is(err, controlstate.ErrPublisherIdentity) || errors.Is(err, controlstate.ErrWorkloadDenied) || errors.Is(err, oidc.ErrUnauthenticated) {
		writeProblem(w, 403, authorityv1.Forbidden, "current machine proof or saved permission does not authorize this operation")
		return
	}
	if errors.Is(err, controlstate.ErrProjectConfigurationInvalid) || errors.Is(err, controlstate.ErrEnvironmentInvalid) {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid machine identity or scoped permission")
		return
	}
	environmentVisitorProblem(ctx, w, err)
}

func (h *handler) machineStore(w http.ResponseWriter) (MachineStore, bool) {
	w.Header().Set("Cache-Control", "no-store")
	s := h.machines
	if s == nil || h.workloads == nil {
		writeProblem(w, 503, authorityv1.Unavailable, "machine authentication is unavailable")
		return nil, false
	}
	return s, true
}

func (h *handler) machineAdmin(w http.ResponseWriter, r *http.Request) (MachineStore, string, bool) {
	s, ok := h.machineStore(w)
	if !ok {
		return nil, "", false
	}
	p, ok := h.authenticateControlRequest(w, r)
	if !ok {
		return nil, "", false
	}
	return s, p.IdentityID, true
}

func (h *handler) RegisterMachineIdentity(w http.ResponseWriter, r *http.Request, team string) {
	s, actor, ok := h.machineAdmin(w, r)
	if !ok {
		return
	}
	var body authorityv1.RegisterMachineRequest
	if decodeJSON(w, r, &body) != nil {
		machineProblem(r.Context(), w, controlstate.ErrProjectConfigurationInvalid)
		return
	}
	request := controlstate.RegisterMachineRequest{TeamID: team, ActorID: actor, Name: body.Name, ProofKind: string(body.ProofKind)}
	if body.KeyId != nil {
		request.KeyID = *body.KeyId
	}
	if body.PublicKey != nil {
		var err error
		request.PublicKey, err = base64.RawURLEncoding.Strict().DecodeString(*body.PublicKey)
		if err != nil {
			machineProblem(r.Context(), w, controlstate.ErrProjectConfigurationInvalid)
			return
		}
	}
	if t := body.Trust; t != nil {
		request.Trust = oidc.WorkloadTrust{Provider: string(t.Provider), Issuer: t.Issuer, JWKSURL: t.JwksUrl, Audience: t.Audience, Claims: t.Claims}
		if t.Events != nil {
			request.Trust.Events = *t.Events
		}
	}
	result, err := s.RegisterMachineIdentity(r.Context(), request, time.Now())
	if err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	response := authorityv1.MachineIdentity{Id: result.ID, TeamId: result.TeamID, Name: result.Name, ProofKind: authorityv1.MachineIdentityProofKind(result.ProofKind), Revision: result.Revision, Trust: body.Trust}
	writeJSON(w, 201, response)
}

func (h *handler) RevokeMachineIdentity(w http.ResponseWriter, r *http.Request, team, machine string) {
	s, actor, ok := h.machineAdmin(w, r)
	if !ok {
		return
	}
	if err := s.RevokeMachineIdentity(r.Context(), team, machine, actor, time.Now()); err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	w.WriteHeader(204)
}

func (h *handler) RotateMachineIdentityKey(w http.ResponseWriter, r *http.Request, team, machine string) {
	s, actor, ok := h.machineAdmin(w, r)
	if !ok {
		return
	}
	var body authorityv1.MachineKey
	if decodeJSON(w, r, &body) != nil {
		machineProblem(r.Context(), w, controlstate.ErrProjectConfigurationInvalid)
		return
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(body.PublicKey)
	if err != nil {
		machineProblem(r.Context(), w, controlstate.ErrProjectConfigurationInvalid)
		return
	}
	if err = s.RotateMachineIdentityKey(r.Context(), team, machine, actor, body.KeyId, public, time.Now()); err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	w.WriteHeader(204)
}

func (h *handler) CreateProvisioningGrant(w http.ResponseWriter, r *http.Request, team, machine string) {
	s, actor, ok := h.machineAdmin(w, r)
	if !ok {
		return
	}
	var body authorityv1.ProvisioningGrantRequest
	if decodeEnvironmentVisitorJSON(w, r, &body, "project_key", "scope", "services", "operations", "max_enrollment_members", "max_enrollment_seconds", "enrollment_budget", "expires_at") != nil {
		machineProblem(r.Context(), w, controlstate.ErrProjectConfigurationInvalid)
		return
	}
	ops := make([]controlstate.ProvisioningOperation, len(body.Operations))
	for i, op := range body.Operations {
		ops[i] = controlstate.ProvisioningOperation(op)
	}
	scope, err := environmentPermissionScopeFromAPI(body.Scope)
	if err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	g, err := s.CreateProvisioningGrant(r.Context(), controlstate.ProvisioningGrant{TeamID: team, MachineID: machine, ProjectKey: body.ProjectKey, Scope: scope, Services: body.Services, Operations: ops, MaxEnrollmentMembers: body.MaxEnrollmentMembers, MaxEnrollmentSeconds: body.MaxEnrollmentSeconds, EnrollmentBudget: body.EnrollmentBudget, ExpiresAt: body.ExpiresAt}, actor, time.Now())
	if err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	writeJSON(w, 201, authorityv1.MachinePermissionResult{Id: g.ID})
}

func (h *handler) RevokeProvisioningGrant(w http.ResponseWriter, r *http.Request, team, grant string) {
	s, actor, ok := h.machineAdmin(w, r)
	if !ok {
		return
	}
	if err := s.RevokeProvisioningGrant(r.Context(), team, grant, actor, time.Now()); err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	w.WriteHeader(204)
}

func (h *handler) CreateEnvironmentVisitorPermission(w http.ResponseWriter, r *http.Request, team, machine string) {
	s, actor, ok := h.machineAdmin(w, r)
	if !ok {
		return
	}
	var body authorityv1.EnvironmentVisitorPermissionRequest
	if decodeEnvironmentVisitorJSON(w, r, &body, "project_key", "scope", "services", "max_duration_seconds", "expires_at") != nil {
		machineProblem(r.Context(), w, controlstate.ErrProjectConfigurationInvalid)
		return
	}
	scope, err := environmentPermissionScopeFromAPI(body.Scope)
	if err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	p, err := s.CreateEnvironmentVisitorPermission(r.Context(), controlstate.EnvironmentVisitorPermission{TeamID: team, MachineID: machine, ProjectKey: body.ProjectKey, Scope: scope, Services: body.Services, MaxDurationSeconds: body.MaxDurationSeconds, ExpiresAt: body.ExpiresAt}, actor, time.Now())
	if err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	writeJSON(w, 201, authorityv1.MachinePermissionResult{Id: p.ID})
}

func (h *handler) RevokeEnvironmentVisitorPermission(w http.ResponseWriter, r *http.Request, team, permission string) {
	s, actor, ok := h.machineAdmin(w, r)
	if !ok {
		return
	}
	if err := s.RevokeEnvironmentVisitorPermission(r.Context(), team, permission, actor, time.Now()); err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	w.WriteHeader(204)
}

type machinePolicyStore interface {
	MachineIdentityPolicy(context.Context, string) (controlstate.MachineIdentity, error)
}

func (h *handler) machineProof(r *http.Request, s machinePolicyStore, id, assertion string) (proof controlstate.MachineProof, err error) {
	proof.Assertion = assertion
	policy, err := s.MachineIdentityPolicy(r.Context(), id)
	if err != nil {
		return proof, err
	}
	if policy.ProofKind == "oidc" {
		proof.Execution, err = h.workloads.Verify(r.Context(), policy.Trust, assertion)
	}
	return proof, err
}

func (h *handler) ExchangeProvisioning(w http.ResponseWriter, r *http.Request) {
	s, ok := h.machineStore(w)
	if !ok {
		return
	}
	var body authorityv1.ProvisioningExchange
	if decodeJSON(w, r, &body) != nil {
		machineProblem(r.Context(), w, controlstate.ErrProjectConfigurationInvalid)
		return
	}
	policy, err := s.ProvisioningIdentityPolicy(r.Context(), body.GrantId, time.Now())
	if err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	if body.MachineId != "" && body.MachineId != policy.ID {
		machineProblem(r.Context(), w, controlstate.ErrMachineDenied)
		return
	}
	proof := controlstate.MachineProof{Assertion: body.Assertion}
	if policy.ProofKind == "oidc" {
		proof.Execution, err = h.workloads.Verify(r.Context(), policy.Trust, body.Assertion)
	}
	if err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	result, err := s.ExchangeProvisioning(r.Context(), policy.ID, body.GrantId, controlstate.ProvisioningOperation(body.Operation), proof, h.config.ControlURL+"/v1/provisioning-sessions/exchange", time.Now())
	if err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	writeJSON(w, 200, result)
}

func environmentPermissionScopeFromAPI(scope authorityv1.EnvironmentPermissionScope) (controlstate.EnvironmentPermissionScope, error) {
	result := controlstate.EnvironmentPermissionScope{IncludeFutureEnvironments: scope.IncludeFutureEnvironments}
	if scope.CollectionId != nil {
		if *scope.CollectionId == "" || scope.EnvironmentIds != nil || scope.IncludeFutureEnvironments == nil {
			return result, controlstate.ErrEnvironmentInvalid
		}
		result.CollectionID = *scope.CollectionId
	} else if scope.IncludeFutureEnvironments != nil || scope.EnvironmentIds == nil {
		return result, controlstate.ErrEnvironmentInvalid
	}
	if scope.EnvironmentIds != nil {
		result.EnvironmentIDs = *scope.EnvironmentIds
	}
	return result, nil
}
