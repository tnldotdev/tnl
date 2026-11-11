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
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

type MachineStore interface {
	RegisterMachineIdentity(context.Context, controlstate.RegisterMachineRequest, time.Time) (controlstate.MachineIdentity, error)
	RotateMachineIdentityKey(context.Context, string, string, string, string, ed25519.PublicKey, time.Time) error
	RevokeMachineIdentity(context.Context, string, string, string, time.Time) error
	MachineIdentityPolicy(context.Context, string) (controlstate.MachineIdentity, error)
	CreateProvisioningGrant(context.Context, controlstate.ProvisioningGrant, string, time.Time) (controlstate.ProvisioningGrant, error)
	RevokeProvisioningGrant(context.Context, string, string, string, time.Time) error
	CreateMachineWorkloadPermission(context.Context, controlstate.MachineWorkloadPermission, string, time.Time) (controlstate.MachineWorkloadPermission, error)
	RevokeMachineWorkloadPermission(context.Context, string, string, string, time.Time) error
	ExchangeProvisioning(context.Context, string, string, controlstate.ProvisioningOperation, controlstate.MachineProof, string, time.Time) (controlstate.ProvisioningSession, error)
	PublisherGroupWorkloadPolicy(context.Context, string, string) (controlstate.ProjectWorkload, error)
	ResolvePublisherGroupWorkload(context.Context, string, string, string, oidc.WorkloadExecution, *controlstate.MachineWorkloadProof, time.Time) (controlstate.PublisherGroupWorkloadResolution, error)
	ExchangeMachineWorkload(context.Context, controlstate.ExchangeWorkloadRequest, controlstate.MachineWorkloadProof, time.Time) (controlstate.WorkloadSession, error)
	MachineWorkloadAssertionPolicy(context.Context, string, string, time.Time) (controlstate.MachineWorkloadProof, error)
	AttachMachineWorkloadAssertion(context.Context, string, string, controlstate.MachineProof, []byte, string, time.Time) (controlstate.WorkloadSession, error)
}

var _ MachineStore = (*controlstate.Database)(nil)

func machineProblem(ctx context.Context, w http.ResponseWriter, err error) {
	if errors.Is(err, controlstate.ErrMachineDenied) || errors.Is(err, controlstate.ErrWorkloadDenied) || errors.Is(err, oidc.ErrUnauthenticated) {
		writeProblem(w, 403, authorityv1.Forbidden, "current machine proof or workload policy does not authorize this operation")
		return
	}
	if errors.Is(err, controlstate.ErrProjectConfigurationInvalid) {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid machine identity or scoped permission")
		return
	}
	workloadProblem(ctx, w, err)
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
	if decodeJSON(w, r, &body) != nil {
		machineProblem(r.Context(), w, controlstate.ErrProjectConfigurationInvalid)
		return
	}
	ops := make([]controlstate.ProvisioningOperation, len(body.Operations))
	for i, op := range body.Operations {
		ops[i] = controlstate.ProvisioningOperation(op)
	}
	g, err := s.CreateProvisioningGrant(r.Context(), controlstate.ProvisioningGrant{TeamID: team, MachineID: machine, ProjectKey: body.ProjectKey, Templates: body.Templates, Operations: ops, MaxEnrollmentMembers: body.MaxEnrollmentMembers, MaxEnrollmentSeconds: body.MaxEnrollmentSeconds, EnrollmentBudget: body.EnrollmentBudget, ExpiresAt: body.ExpiresAt}, actor, time.Now())
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

func (h *handler) CreateMachineWorkloadPermission(w http.ResponseWriter, r *http.Request, team, machine string) {
	s, actor, ok := h.machineAdmin(w, r)
	if !ok {
		return
	}
	var body authorityv1.MachineWorkloadPermissionRequest
	if decodeJSON(w, r, &body) != nil {
		machineProblem(r.Context(), w, controlstate.ErrProjectConfigurationInvalid)
		return
	}
	p, err := s.CreateMachineWorkloadPermission(r.Context(), controlstate.MachineWorkloadPermission{TeamID: team, MachineID: machine, ProjectKey: body.ProjectKey, Workload: body.Workload, Templates: body.Templates, ExpiresAt: body.ExpiresAt}, actor, time.Now())
	if err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	writeJSON(w, 201, authorityv1.MachinePermissionResult{Id: p.ID})
}

func (h *handler) RevokeMachineWorkloadPermission(w http.ResponseWriter, r *http.Request, team, permission string) {
	s, actor, ok := h.machineAdmin(w, r)
	if !ok {
		return
	}
	if err := s.RevokeMachineWorkloadPermission(r.Context(), team, permission, actor, time.Now()); err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	w.WriteHeader(204)
}

func (h *handler) machineProof(r *http.Request, s MachineStore, id, assertion string) (proof controlstate.MachineProof, err error) {
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
	proof, err := h.machineProof(r, s, body.MachineId, body.Assertion)
	if err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	result, err := s.ExchangeProvisioning(r.Context(), body.MachineId, body.GrantId, controlstate.ProvisioningOperation(body.Operation), proof, h.config.ControlURL+"/v1/provisioning-sessions/exchange", time.Now())
	if err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	writeJSON(w, 200, result)
}

func (h *handler) ResolvePublisherGroupWorkload(w http.ResponseWriter, r *http.Request, group string) {
	s, ok := h.machineStore(w)
	if !ok {
		return
	}
	var body authorityv1.ResolvePublisherGroupWorkload
	if decodeJSON(w, r, &body) != nil {
		machineProblem(r.Context(), w, controlstate.ErrProjectConfigurationInvalid)
		return
	}
	var execution oidc.WorkloadExecution
	var machine *controlstate.MachineWorkloadProof
	if body.MachineId != nil {
		proof, err := h.machineProof(r, s, *body.MachineId, body.Assertion)
		if err != nil {
			machineProblem(r.Context(), w, err)
			return
		}
		machine = &controlstate.MachineWorkloadProof{MachineID: *body.MachineId, GroupID: group, Proof: proof, Audience: h.config.ControlURL + "/v1/publisher-groups/" + group + "/resolve"}
	} else {
		policy, err := s.PublisherGroupWorkloadPolicy(r.Context(), group, body.Workload)
		if err != nil {
			machineProblem(r.Context(), w, err)
			return
		}
		execution, err = h.workloads.Verify(r.Context(), policy.Trust, body.Assertion)
		if err != nil {
			machineProblem(r.Context(), w, err)
			return
		}
	}
	result, err := s.ResolvePublisherGroupWorkload(r.Context(), group, body.Workload, h.config.ControlURL, execution, machine, time.Now())
	if err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	writeJSON(w, 200, result)
}

func (h *handler) ExchangeMachineWorkload(w http.ResponseWriter, r *http.Request) {
	s, ok := h.machineStore(w)
	if !ok {
		return
	}
	var body authorityv1.MachineWorkloadExchange
	if decodeJSON(w, r, &body) != nil {
		machineProblem(r.Context(), w, controlstate.ErrProjectConfigurationInvalid)
		return
	}
	b := body.Exchange
	public, err := base64.RawURLEncoding.Strict().DecodeString(b.PublicKey)
	if err != nil || len(public) != 32 {
		machineProblem(r.Context(), w, controlstate.ErrProjectConfigurationInvalid)
		return
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(b.Signature)
	if err != nil || len(signature) != 64 {
		machineProblem(r.Context(), w, controlstate.ErrProjectConfigurationInvalid)
		return
	}
	proof, err := h.machineProof(r, s, body.MachineId, b.Assertion)
	if err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	var services []string
	if b.Services != nil {
		services = *b.Services
	}
	result, err := s.ExchangeMachineWorkload(r.Context(), controlstate.ExchangeWorkloadRequest{TeamID: b.TeamId, ProjectKey: b.ProjectKey, Workload: b.Workload, SourceFingerprint: b.SourceFingerprint, Nonce: b.Nonce, PublicKey: public, Signature: signature, Services: services}, controlstate.MachineWorkloadProof{MachineID: body.MachineId, GroupID: body.GroupId, Proof: proof, Audience: h.config.ControlURL + "/v1/machine-workload-sessions/exchange"}, time.Now())
	if err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	// the state caps assertion expiry to the separately approved permission.
	result.AssertionExpiresAt = new(result.IdentityExpiresAt)
	writeJSON(w, 200, result)
}

func (h *handler) AttachMachineWorkloadAssertion(w http.ResponseWriter, r *http.Request, id string) {
	s, ok := h.machineStore(w)
	if !ok {
		return
	}
	token, err := credentials.Bearer(r.Header)
	if err != nil {
		writeBearerProblem(w)
		return
	}
	var body authorityv1.WorkloadAssertion
	if decodeJSON(w, r, &body) != nil {
		machineProblem(r.Context(), w, controlstate.ErrProjectConfigurationInvalid)
		return
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		machineProblem(r.Context(), w, controlstate.ErrProjectConfigurationInvalid)
		return
	}
	policy, err := s.MachineWorkloadAssertionPolicy(r.Context(), id, token, time.Now())
	if err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	proof, err := h.machineProof(r, s, policy.MachineID, body.Assertion)
	if err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	result, err := s.AttachMachineWorkloadAssertion(r.Context(), id, token, proof, signature, h.config.ControlURL+"/v1/machine-workload-sessions/"+id+"/assertions", time.Now())
	if err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	writeJSON(w, 200, result)
}
