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

type WorkloadStore interface {
	WorkloadPolicy(context.Context, string, string, string, string) (controlstate.ProjectWorkload, error)
	ExchangeWorkload(context.Context, controlstate.ExchangeWorkloadRequest, time.Time) (controlstate.WorkloadSession, error)
	RenewWorkloadSession(context.Context, string, string, time.Time) (controlstate.WorkloadSession, error)
	RevokeWorkloadSession(context.Context, string, string, time.Time) error
	IdentifyWorkload(context.Context, string, string, string, string, oidc.WorkloadExecution, time.Time) (string, error)
	WorkloadAssertionPolicy(context.Context, string, string) (controlstate.ProjectWorkload, error)
	AttachWorkloadAssertion(context.Context, string, string, oidc.WorkloadExecution, []byte, time.Time) (controlstate.WorkloadSession, error)
}

func (h *handler) IdentifyWorkload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	store, ok := h.store.(WorkloadStore)
	if !ok || h.workloads == nil {
		writeProblem(w, 503, authorityv1.Unavailable, "workload authentication is unavailable")
		return
	}
	var body authorityv1.WorkloadIdentityRequest
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid workload identity request")
		return
	}
	p, err := store.WorkloadPolicy(r.Context(), body.TeamId, body.ProjectKey, body.Workload, body.SourceFingerprint)
	if err != nil {
		workloadProblem(w, err)
		return
	}
	c, err := h.workloads.Verify(r.Context(), p.Trust, body.Assertion)
	if err != nil {
		workloadProblem(w, err)
		return
	}
	binding, err := store.IdentifyWorkload(r.Context(), body.TeamId, body.ProjectKey, body.Workload, body.SourceFingerprint, c, time.Now())
	if err != nil {
		workloadProblem(w, err)
		return
	}
	writeJSON(w, 200, authorityv1.WorkloadIdentity{Binding: binding, Services: p.Services, AssertionExpiresAt: time.Unix(c.ExpiresAt, 0)})
}

func (h *handler) AttachWorkloadAssertion(w http.ResponseWriter, r *http.Request, id string) {
	w.Header().Set("Cache-Control", "no-store")
	token, err := credentials.Bearer(r.Header)
	if err != nil {
		writeBearerProblem(w)
		return
	}
	store, ok := h.store.(WorkloadStore)
	if !ok || h.workloads == nil {
		writeProblem(w, 503, authorityv1.Unavailable, "workload authentication is unavailable")
		return
	}
	var body authorityv1.WorkloadAssertion
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid workload assertion attachment")
		return
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
	if err != nil || len(signature) != 64 {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid workload key proof")
		return
	}
	p, err := store.WorkloadAssertionPolicy(r.Context(), id, token)
	if err != nil {
		workloadProblem(w, err)
		return
	}
	c, err := h.workloads.Verify(r.Context(), p.Trust, body.Assertion)
	if err != nil {
		workloadProblem(w, err)
		return
	}
	result, err := store.AttachWorkloadAssertion(r.Context(), id, token, c, signature, time.Now())
	if err != nil {
		workloadProblem(w, err)
		return
	}
	result.AssertionExpiresAt = new(time.Unix(c.ExpiresAt, 0))
	writeJSON(w, 200, result)
}

func workloadProblem(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, controlstate.ErrWorkloadExpired):
		writeProblem(w, 410, authorityv1.Forbidden, "workload session expired; a current assertion may authorize a new session for future connections")
	case errors.Is(err, controlstate.ErrWorkloadDenied), errors.Is(err, oidc.ErrUnauthenticated):
		writeProblem(w, 403, authorityv1.Forbidden, "workload assertion or saved workload policy does not authorize this execution")
	case errors.Is(err, controlstate.ErrWorkloadConflict):
		writeProblem(w, 409, authorityv1.Conflict, "workload execution is already bound to another key or service scope; resume with the original ephemeral key")
	case errors.Is(err, oidc.ErrUnavailable):
		writeProblem(w, 503, authorityv1.Unavailable, "provider signing keys are unavailable; retry this exchange")
	default:
		writeControlStateProblem(w, "authorize workload session", err)
	}
}

func (h *handler) ExchangeWorkload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	store, ok := h.store.(WorkloadStore)
	if !ok || h.workloads == nil {
		writeProblem(w, 503, authorityv1.Unavailable, "workload authentication is unavailable")
		return
	}
	var body authorityv1.WorkloadExchange
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid workload exchange")
		return
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(body.PublicKey)
	if err != nil || len(public) != 32 {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid workload public key")
		return
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
	if err != nil || len(signature) != 64 {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid workload key proof")
		return
	}
	policy, err := store.WorkloadPolicy(r.Context(), body.TeamId, body.ProjectKey, body.Workload, body.SourceFingerprint)
	if err != nil {
		workloadProblem(w, err)
		return
	}
	execution, err := h.workloads.Verify(r.Context(), policy.Trust, body.Assertion)
	if err != nil {
		workloadProblem(w, err)
		return
	}
	var services []string
	if body.Services != nil {
		services = *body.Services
	}
	result, err := store.ExchangeWorkload(r.Context(), controlstate.ExchangeWorkloadRequest{TeamID: body.TeamId, ProjectKey: body.ProjectKey, Workload: body.Workload, SourceFingerprint: body.SourceFingerprint, Nonce: body.Nonce, Execution: execution, PublicKey: ed25519.PublicKey(public), Signature: signature, Services: services}, time.Now())
	if err != nil {
		workloadProblem(w, err)
		return
	}
	result.AssertionExpiresAt = new(time.Unix(execution.ExpiresAt, 0))
	writeJSON(w, 200, result)
}

func (h *handler) RenewWorkloadSession(w http.ResponseWriter, r *http.Request, id string) {
	w.Header().Set("Cache-Control", "no-store")
	token, err := credentials.Bearer(r.Header)
	if err != nil {
		writeBearerProblem(w)
		return
	}
	store, ok := h.store.(WorkloadStore)
	if !ok {
		writeProblem(w, 503, authorityv1.Unavailable, "workload authentication is unavailable")
		return
	}
	result, err := store.RenewWorkloadSession(r.Context(), id, token, time.Now())
	if err != nil {
		workloadProblem(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (h *handler) RevokeWorkloadSession(w http.ResponseWriter, r *http.Request, id string) {
	w.Header().Set("Cache-Control", "no-store")
	token, err := credentials.Bearer(r.Header)
	if err != nil {
		writeBearerProblem(w)
		return
	}
	store, ok := h.store.(WorkloadStore)
	if !ok {
		writeProblem(w, 503, authorityv1.Unavailable, "workload authentication is unavailable")
		return
	}
	if err = store.RevokeWorkloadSession(r.Context(), id, token, time.Now()); err != nil {
		workloadProblem(w, err)
		return
	}
	w.WriteHeader(204)
}
