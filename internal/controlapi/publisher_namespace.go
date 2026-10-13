package controlapi

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) allocatePublisherNamespace(w http.ResponseWriter, r *http.Request, body controlv1.AllocateEphemeralPublicURLRequest) {
	machine, ok := h.authenticatePublisherAccess(w, r)
	if !ok {
		return
	}
	if machine.Scope.Kind != "namespace" || machine.CreatorID == "" || machine.GuestID != "" {
		writeBearerProblem(w)
		return
	}
	prefixes, err := allocationIPPolicy(r, body)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid ad-hoc visitor IP policy")
		return
	}
	bound, err := json.Marshal(struct {
		PublisherIdentityID, GrantID, InvocationID, Target string
		Prefixes                                           []string
		Limits                                             *controlv1.PublisherApplicationLimits
	}{machine.ID, machine.GrantID, body.InvocationId, body.Target, prefixes, body.Limits})
	if err != nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid ad-hoc allocation request")
		return
	}
	result, err := h.store.CreatePublicURL(r.Context(), controlstate.CreatePublicURLRequest{
		TeamID: machine.Scope.TeamID, DomainID: machine.Scope.DomainID, ActingIdentityID: machine.CreatorID,
		IdempotencyKey: machine.ID + ":" + body.InvocationId, RequestDigest: sha256.Sum256(bound),
		Target: body.Target, PublicURLScope: controlstate.PublicURLScopeMember, Purpose: controlstate.PublicURLPurposeApp,
		ManagedURLMode: h.config.ManagedURLMode, AllowedIPPrefixes: prefixes,
		DNSState: controlstate.PublicURLDNSPending, Ephemeral: true,
		PublisherIdentityID: machine.ID, PublisherGrantID: machine.GrantID,
		PublisherNamespace: machine.Scope.Namespace, PublisherInvocationID: body.InvocationId,
	}, time.Now().UTC())
	if errors.Is(err, controlstate.ErrPublicURLAccess) || errors.Is(err, controlstate.ErrPublisherIdentity) {
		writeProblem(w, http.StatusForbidden, controlv1.Forbidden, "publisher namespace grant is no longer authorized")
		return
	}
	if err != nil {
		writeControlStateProblem(w, "allocate publisher public URL", err)
		return
	}
	writeJSON(w, http.StatusCreated, publicURLResponse(result))
}
