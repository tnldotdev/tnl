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
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type EnvironmentVisitorStore interface {
	EnvironmentVisitorIdentityPolicy(context.Context, string, time.Time) (controlstate.MachineIdentity, error)
	PrepareEnvironmentVisitor(context.Context, controlstate.PrepareEnvironmentVisitorRequest, time.Time) (controlstate.EnvironmentVisitorPreparation, error)
	RenewEnvironmentVisitorSession(context.Context, string, string, controlstate.WorkloadRenewal, time.Time) (controlstate.WorkloadSession, error)
	RevokeEnvironmentVisitorSession(context.Context, string, string, time.Time) error
	EnvironmentVisitorAssertionPolicy(context.Context, string, string, time.Time) (controlstate.MachineIdentity, error)
	AttachEnvironmentVisitorAssertion(context.Context, string, string, controlstate.MachineProof, []byte, string, time.Time) (controlstate.WorkloadSession, error)
}

var _ EnvironmentVisitorStore = (*controlstate.Database)(nil)

func environmentVisitorProblem(ctx context.Context, w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, controlstate.ErrEnvironmentInvalid):
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid environment visitor selection or key proof")
	case errors.Is(err, controlstate.ErrWorkloadExpired):
		writeProblem(w, 410, authorityv1.Forbidden, "visitor session expired; prepare a new session with a current identity proof")
	case errors.Is(err, controlstate.ErrWorkloadDenied), errors.Is(err, controlstate.ErrMachineDenied), errors.Is(err, oidc.ErrUnauthenticated):
		writeProblem(w, 403, authorityv1.Forbidden, "current identity or saved environment permission does not authorize this operation")
	case errors.Is(err, controlstate.ErrWorkloadConflict):
		writeProblem(w, 409, authorityv1.Conflict, "visitor session is already bound to another key or service scope; resume with the original key and selection")
	case errors.Is(err, oidc.ErrUnavailable):
		writeProblem(w, 503, authorityv1.Unavailable, "provider signing keys are unavailable; retry this request")
	default:
		writeControlStateProblem(ctx, w, "authorize environment visitor", err)
	}
}

func (h *handler) environmentVisitorStore(w http.ResponseWriter) (EnvironmentVisitorStore, bool) {
	w.Header().Set("Cache-Control", "no-store")
	if h.store == nil || h.workloads == nil {
		writeProblem(w, 503, authorityv1.Unavailable, "environment visitor authentication is unavailable")
		return nil, false
	}
	return h.store, true
}

func (h *handler) verifiedMachineProof(r *http.Request, policy controlstate.MachineIdentity, assertion string) (proof controlstate.MachineProof, err error) {
	proof.Assertion = assertion
	if policy.ProofKind == "oidc" {
		proof.Execution, err = h.workloads.Verify(r.Context(), policy.Trust, assertion)
	}
	return proof, err
}

func environmentVisitorSessionResponse(s controlstate.WorkloadSession) authorityv1.EnvironmentVisitorSession {
	return authorityv1.EnvironmentVisitorSession{Id: s.ID, Credential: s.Credential, ExpiresAt: s.ExpiresAt,
		IdentityExpiresAt: s.IdentityExpiresAt, LeaseExpiresAt: s.LeaseExpiresAt, RenewAfter: s.RenewAfter,
		RenewalSequence: s.RenewalSequence, ServiceIds: s.ServiceIDs,
		Subject: controlv1.VisitorSubject{Kind: controlv1.VisitorSubjectKind(s.Subject.Kind), WorkloadSessionId: new(s.ID)}}
}

func (h *handler) PrepareEnvironmentVisitor(w http.ResponseWriter, r *http.Request, project, environment string) {
	s, ok := h.environmentVisitorStore(w)
	if !ok {
		return
	}
	var body authorityv1.EnvironmentVisitorPrepareRequest
	if decodeEnvironmentVisitorJSON(w, r, &body, "permission_id", "assertion", "nonce", "public_key", "services", "signature") != nil {
		environmentVisitorProblem(r.Context(), w, controlstate.ErrEnvironmentInvalid)
		return
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(body.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		environmentVisitorProblem(r.Context(), w, controlstate.ErrEnvironmentInvalid)
		return
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		environmentVisitorProblem(r.Context(), w, controlstate.ErrEnvironmentInvalid)
		return
	}
	policy, err := s.EnvironmentVisitorIdentityPolicy(r.Context(), body.PermissionId, time.Now())
	if err != nil {
		environmentVisitorProblem(r.Context(), w, err)
		return
	}
	proof, err := h.verifiedMachineProof(r, policy, body.Assertion)
	if err != nil {
		environmentVisitorProblem(r.Context(), w, err)
		return
	}
	services := make(map[string]string, len(body.Services))
	for name, protocol := range body.Services {
		services[name] = string(protocol)
	}
	result, err := s.PrepareEnvironmentVisitor(r.Context(), controlstate.PrepareEnvironmentVisitorRequest{ProjectKey: project,
		EnvironmentID: environment, PermissionID: body.PermissionId, Nonce: body.Nonce, PublicKey: public, Signature: signature,
		Services: services, Proof: proof, Audience: h.config.ControlURL + r.URL.EscapedPath()}, time.Now())
	if err != nil {
		environmentVisitorProblem(r.Context(), w, err)
		return
	}
	response := authorityv1.EnvironmentVisitorPreparation{Environment: controlv1.EnvironmentReference{Server: h.config.ControlURL, ProjectKey: result.ProjectKey, EnvironmentId: result.EnvironmentID},
		AppliedDefinitionRevision: result.AppliedDefinitionRevision, MutationRevision: result.MutationRevision,
		Session: environmentVisitorSessionResponse(result.Session), Services: make(map[string]authorityv1.EnvironmentVisitorService, len(result.Services))}
	for name, service := range result.Services {
		response.Services[name] = authorityv1.EnvironmentVisitorService{ServiceId: service.ID, Protocol: controlv1.ServiceProtocol(service.Protocol),
			Endpoint: controlv1.ServiceEndpoint{Hostname: service.Endpoint.Hostname, Port: service.Endpoint.Port, Public: service.Endpoint.Public}, KubernetesAuth: service.KubernetesAuth}
	}
	writeJSON(w, 200, response)
}

func (h *handler) AttachEnvironmentVisitorAssertion(w http.ResponseWriter, r *http.Request, id string) {
	s, ok := h.environmentVisitorStore(w)
	if !ok {
		return
	}
	token, err := credentials.Bearer(r.Header)
	if err != nil {
		writeBearerProblem(w)
		return
	}
	var body authorityv1.EnvironmentVisitorAssertion
	if decodeEnvironmentVisitorJSON(w, r, &body, "assertion", "signature") != nil {
		environmentVisitorProblem(r.Context(), w, controlstate.ErrEnvironmentInvalid)
		return
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		environmentVisitorProblem(r.Context(), w, controlstate.ErrEnvironmentInvalid)
		return
	}
	policy, err := s.EnvironmentVisitorAssertionPolicy(r.Context(), id, token, time.Now())
	if err != nil {
		environmentVisitorProblem(r.Context(), w, err)
		return
	}
	proof, err := h.verifiedMachineProof(r, policy, body.Assertion)
	if err != nil {
		environmentVisitorProblem(r.Context(), w, err)
		return
	}
	result, err := s.AttachEnvironmentVisitorAssertion(r.Context(), id, token, proof, signature, h.config.ControlURL+r.URL.EscapedPath(), time.Now())
	if err != nil {
		environmentVisitorProblem(r.Context(), w, err)
		return
	}
	writeJSON(w, 200, environmentVisitorSessionResponse(result))
}

func (h *handler) RenewEnvironmentVisitorSession(w http.ResponseWriter, r *http.Request, id string) {
	s, ok := h.environmentVisitorStore(w)
	if !ok {
		return
	}
	token, err := credentials.Bearer(r.Header)
	if err != nil {
		writeBearerProblem(w)
		return
	}
	var body authorityv1.EnvironmentVisitorRenewal
	if decodeEnvironmentVisitorJSON(w, r, &body, "sequence", "signature") != nil {
		environmentVisitorProblem(r.Context(), w, controlstate.ErrEnvironmentInvalid)
		return
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || body.Sequence <= 0 {
		environmentVisitorProblem(r.Context(), w, controlstate.ErrEnvironmentInvalid)
		return
	}
	result, err := s.RenewEnvironmentVisitorSession(r.Context(), id, token, controlstate.WorkloadRenewal{Sequence: body.Sequence, Signature: signature}, time.Now())
	if err != nil {
		environmentVisitorProblem(r.Context(), w, err)
		return
	}
	writeJSON(w, 200, environmentVisitorSessionResponse(result))
}

func (h *handler) RevokeEnvironmentVisitorSession(w http.ResponseWriter, r *http.Request, id string) {
	s, ok := h.environmentVisitorStore(w)
	if !ok {
		return
	}
	token, err := credentials.Bearer(r.Header)
	if err != nil {
		writeBearerProblem(w)
		return
	}
	if err = s.RevokeEnvironmentVisitorSession(r.Context(), id, token, time.Now()); err != nil {
		environmentVisitorProblem(r.Context(), w, err)
		return
	}
	w.WriteHeader(204)
}
