package authority

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/control/oidc"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

type MachinePublicationStore interface {
	MachineIdentityPolicy(context.Context, string) (controlstate.MachineIdentity, error)
	CreateMachinePublicationPermission(context.Context, controlstate.MachinePublicationPermission, string, time.Time) (controlstate.MachinePublicationPermission, error)
	RevokeMachinePublicationPermission(context.Context, string, string, string, time.Time) error
	MachinePublicationCandidates(context.Context, controlstate.MachinePublicationLookup, time.Time) ([]controlstate.MachineIdentity, error)
	ExchangeMachinePublication(context.Context, controlstate.MachinePublicationExchange, string, time.Time) (controlstate.MachinePublicationSession, error)
	RefreshMachinePublication(context.Context, string, controlstate.MachineProof, []byte, string, time.Time) (controlstate.MachinePublicationSession, error)
	CleanupMachinePublication(context.Context, string, string, string, string, time.Time) error
}

var _ MachinePublicationStore = (*controlstate.Database)(nil)

func (h *handler) publicationStore(w http.ResponseWriter) (MachinePublicationStore, bool) {
	w.Header().Set("Cache-Control", "no-store")
	if h.publications == nil || h.workloads == nil {
		writeProblem(w, 503, authorityv1.Unavailable, "machine publication authentication is unavailable")
		return nil, false
	}
	return h.publications, true
}

func (h *handler) publicationAdmin(w http.ResponseWriter, r *http.Request) (MachinePublicationStore, string, bool) {
	s, ok := h.publicationStore(w)
	if !ok {
		return nil, "", false
	}
	p, ok := h.authenticateControlRequest(w, r)
	if !ok {
		return nil, "", false
	}
	return s, p.IdentityID, true
}

func (h *handler) CreateMachinePublicationPermission(w http.ResponseWriter, r *http.Request, team, machine string) {
	s, actor, ok := h.publicationAdmin(w, r)
	if !ok {
		return
	}
	var body authorityv1.MachinePublicationPermissionRequest
	if decodeJSON(w, r, &body) != nil {
		machineProblem(r.Context(), w, controlstate.ErrProjectConfigurationInvalid)
		return
	}
	result, err := s.CreateMachinePublicationPermission(r.Context(), controlstate.MachinePublicationPermission{MachineID: machine, TeamID: team, Resource: body.Resource, Namespace: body.Namespace, DomainID: body.DomainId, AllowAnonymous: body.AllowAnonymous, ExpiresAt: body.ExpiresAt}, actor, time.Now())
	if err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	writeJSON(w, 201, authorityv1.MachinePermissionResult{Id: result.ID})
}

func (h *handler) RevokeMachinePublicationPermission(w http.ResponseWriter, r *http.Request, team, id string) {
	s, actor, ok := h.publicationAdmin(w, r)
	if !ok {
		return
	}
	if err := s.RevokeMachinePublicationPermission(r.Context(), team, id, actor, time.Now()); err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	w.WriteHeader(204)
}

func (h *handler) publicationProof(r *http.Request, s MachinePublicationStore, resource, namespace, session, selected, assertion string) (string, controlstate.MachineProof, error) {
	lookup := controlstate.MachinePublicationLookup{Resource: resource, Namespace: namespace, SessionID: session, MachineID: selected}
	if session == "" && selected == "" {
		hint, err := oidc.UnverifiedWorkloadIdentity(assertion)
		if err != nil {
			return "", controlstate.MachineProof{}, err
		}
		lookup.Hint = hint
	}
	candidates, err := s.MachinePublicationCandidates(r.Context(), lookup, time.Now())
	if err != nil {
		return "", controlstate.MachineProof{}, err
	}
	var identity string
	var proof controlstate.MachineProof
	var unavailable error
	for _, candidate := range candidates {
		if selected != "" && selected != candidate.ID {
			continue
		}
		current := controlstate.MachineProof{Assertion: assertion}
		if candidate.ProofKind == "oidc" {
			current.Execution, err = h.workloads.Verify(r.Context(), candidate.Trust, assertion)
			if err != nil {
				if errors.Is(err, oidc.ErrUnavailable) {
					unavailable = err
				}
				continue
			}
		} else if candidate.ProofKind != "signing_key" || selected == "" {
			continue
		}
		if identity != "" {
			return "", proof, controlstate.ErrMachineDenied
		}
		identity = candidate.ID
		proof = current
	}
	if identity == "" {
		if unavailable != nil {
			return "", proof, unavailable
		}
		return "", proof, controlstate.ErrMachineDenied
	}
	return identity, proof, nil
}

func (h *handler) ExchangeMachinePublication(w http.ResponseWriter, r *http.Request) {
	s, ok := h.publicationStore(w)
	if !ok {
		return
	}
	var body authorityv1.MachinePublicationExchange
	if decodeJSON(w, r, &body) != nil {
		machineProblem(r.Context(), w, controlstate.ErrProjectConfigurationInvalid)
		return
	}
	if (body.Resource == "") == (body.Namespace == "") {
		machineProblem(r.Context(), w, controlstate.ErrMachineDenied)
		return
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(body.PublicKey)
	if err != nil || len(public) != 32 {
		machineProblem(r.Context(), w, controlstate.ErrProjectConfigurationInvalid)
		return
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
	if err != nil || len(signature) != 64 {
		machineProblem(r.Context(), w, controlstate.ErrProjectConfigurationInvalid)
		return
	}
	machine, proof, err := h.publicationProof(r, s, body.Resource, body.Namespace, "", body.MachineId, body.Assertion)
	if err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	result, err := s.ExchangeMachinePublication(r.Context(), controlstate.MachinePublicationExchange{MachineID: machine, Resource: body.Resource, Namespace: body.Namespace, Nonce: body.Nonce, PublicKey: public, Signature: signature, Proof: proof}, h.config.ControlURL+"/v1/machine-publication-sessions/exchange", time.Now())
	if err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	writeJSON(w, 200, result)
}

func (h *handler) RefreshMachinePublication(w http.ResponseWriter, r *http.Request, id string) {
	s, ok := h.publicationStore(w)
	if !ok {
		return
	}
	var body authorityv1.MachinePublicationRefresh
	if decodeJSON(w, r, &body) != nil {
		machineProblem(r.Context(), w, controlstate.ErrProjectConfigurationInvalid)
		return
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
	if err != nil || len(signature) != 64 {
		machineProblem(r.Context(), w, controlstate.ErrProjectConfigurationInvalid)
		return
	}
	// the session selects exactly one saved identity. signing-key callers need
	// not repeat its ID on refresh; possession and current key are checked below.
	candidates, err := s.MachinePublicationCandidates(r.Context(), controlstate.MachinePublicationLookup{SessionID: id}, time.Now())
	if err != nil || len(candidates) != 1 {
		if err == nil {
			err = controlstate.ErrMachineDenied
		}
		machineProblem(r.Context(), w, err)
		return
	}
	proof, err := h.machineProof(r, s, candidates[0].ID, body.Assertion)
	if err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	result, err := s.RefreshMachinePublication(r.Context(), id, proof, signature, h.config.ControlURL+"/v1/machine-publication-sessions/"+id+"/refresh", time.Now())
	if err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	writeJSON(w, 200, result)
}

func (h *handler) CleanupMachinePublication(w http.ResponseWriter, r *http.Request, id string) {
	w.Header().Set("Cache-Control", "no-store")
	// removal needs the native key only, even when source verification is down.
	if h.publications == nil {
		writeProblem(w, 503, authorityv1.Unavailable, "machine publication cleanup is unavailable")
		return
	}
	var body authorityv1.MachinePublicationCleanup
	if decodeJSON(w, r, &body) != nil {
		machineProblem(r.Context(), w, controlstate.ErrProjectConfigurationInvalid)
		return
	}
	if err := h.publications.CleanupMachinePublication(r.Context(), id, body.InvocationId, body.Assertion, h.config.ControlURL+"/v1/machine-publication-sessions/"+id+"/cleanup", time.Now()); err != nil {
		machineProblem(r.Context(), w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
