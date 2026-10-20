package authorityapi

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

type WorkloadStore interface {
	ExchangeGitHubWorkload(context.Context, controlstate.ExchangeGitHubWorkloadRequest, time.Time) (controlstate.WorkloadSession, error)
	RenewWorkloadSession(context.Context, string, string, time.Time) (controlstate.WorkloadSession, error)
	RevokeWorkloadSession(context.Context, string, string, time.Time) error
}

func workloadProblem(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, controlstate.ErrWorkloadDenied), errors.Is(err, oidcauth.ErrUnauthenticated):
		writeProblem(w, 403, authorityv1.Forbidden, "workload assertion or saved ci policy does not authorize this execution")
	case errors.Is(err, controlstate.ErrWorkloadConflict):
		writeProblem(w, 409, authorityv1.Conflict, "workload execution is already bound to another key or service scope; resume with the original ephemeral key")
	case errors.Is(err, oidcauth.ErrUnavailable):
		writeProblem(w, 503, authorityv1.Unavailable, "GitHub signing keys are unavailable; retry this exchange")
	default:
		writeControlStateProblem(w, "authorize workload session", err)
	}
}

func (h *handler) ExchangeGitHubWorkload(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	store, ok := h.store.(WorkloadStore)
	if !ok || h.workloads == nil {
		writeProblem(w, 503, authorityv1.Unavailable, "workload authentication is unavailable")
		return
	}
	var body authorityv1.GitHubWorkloadExchange
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
	execution, err := h.workloads.Verify(r.Context(), body.Assertion)
	if err != nil {
		workloadProblem(w, err)
		return
	}
	var services []string
	if body.Services != nil {
		services = *body.Services
	}
	result, err := store.ExchangeGitHubWorkload(r.Context(), controlstate.ExchangeGitHubWorkloadRequest{TeamID: body.TeamId, ProjectKey: body.ProjectKey, CI: body.Ci, Execution: execution, PublicKey: ed25519.PublicKey(public), Signature: signature, Services: services}, time.Now())
	if err != nil {
		workloadProblem(w, err)
		return
	}
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
