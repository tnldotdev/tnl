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

func (h *handler) authenticatePublisherAccess(w http.ResponseWriter, r *http.Request) (controlstate.PublisherIdentity, bool) {
	if h.publisherIdentities == nil {
		writeBearerProblem(w)
		return controlstate.PublisherIdentity{}, false
	}
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return controlstate.PublisherIdentity{}, false
	}
	identity, err := h.publisherIdentities.AuthenticatePublisherAccess(r.Context(), token, time.Now().UTC())
	if errors.Is(err, controlstate.ErrPublisherIdentity) {
		writeBearerProblem(w)
		return controlstate.PublisherIdentity{}, false
	}
	if err != nil {
		writeControlStateProblem(w, "authenticate publisher", err)
		return controlstate.PublisherIdentity{}, false
	}
	return identity, true
}

func (h *handler) GetPublisherPublicURL(w http.ResponseWriter, r *http.Request) {
	machine, ok := h.authenticatePublisherAccess(w, r)
	if !ok {
		return
	}
	if machine.Scope.Kind != "saved_url" {
		writeBearerProblem(w)
		return
	}
	route, err := h.store.GetPublicURLForAuthorization(r.Context(), machine.Scope.PublicURLID)
	if err != nil {
		writeControlStateProblem(w, "read publisher public URL", err)
		return
	}
	if route.TeamID != machine.Scope.TeamID || route.Ephemeral || route.LifecycleState != controlstate.PublicURLLifecycleEnabled {
		writeProblem(w, http.StatusNotFound, controlv1.NotFound, "publisher public URL is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, publicURLResponse(route))
}

func (h *handler) allocatePublisherNamespace(w http.ResponseWriter, r *http.Request, body controlv1.AllocateEphemeralPublicURLRequest) {
	machine, ok := h.authenticatePublisherAccess(w, r)
	if !ok {
		return
	}
	if machine.Scope.Kind != "namespace" || machine.CreatorID == "" {
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
	if errors.Is(err, controlstate.ErrPublicURLAccess) {
		writeProblem(w, http.StatusForbidden, controlv1.Forbidden, "publisher namespace grant is no longer authorized")
		return
	}
	if err != nil {
		writeControlStateProblem(w, "allocate publisher public URL", err)
		return
	}
	writeJSON(w, http.StatusCreated, publicURLResponse(result))
}
