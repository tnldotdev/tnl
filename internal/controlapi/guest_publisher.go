package controlapi

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) RegisterGuestPublisherIdentity(w http.ResponseWriter, r *http.Request) {
	if !h.config.GuestDemoEnabled || h.guests == nil || h.publisherIdentities == nil {
		writeProblem(w, http.StatusNotFound, controlv1.NotFound, "guest demos are unavailable")
		return
	}
	var body controlv1.RegisterGuestPublisherIdentityRequest
	if err := decodeJSONLimited(w, r, &body, 1024); err != nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid guest publisher key")
		return
	}
	key, err := base64.RawURLEncoding.DecodeString(body.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid guest publisher key")
		return
	}
	access, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	guest, err := h.guests.GuestTrialByAccessToken(r.Context(), credentials.AccessToken(access))
	if errors.Is(err, controlstate.ErrGuestUnknown) {
		writeBearerProblem(w)
		return
	}
	if err != nil {
		writeControlStateProblem(w, "authenticate guest trial", err)
		return
	}
	now := time.Now().UTC()
	if !guest.ExpiresAt.After(now) || guest.UsedReady >= controlstate.GuestReadyAllowance || guest.UsedBytes >= controlstate.GuestByteAllowance {
		writeProblem(w, http.StatusForbidden, controlv1.GuestTrialExhausted, "guest demo trial ended; run tnl auth login to continue")
		return
	}
	address, err := guestRequestAddress(r)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid client address")
		return
	}
	matched, err := h.publisherIdentities.GuestPublisherSourceMatches(r.Context(), guest.ID, address)
	if err != nil {
		writeControlStateProblem(w, "check guest IP", err)
		return
	}
	if !matched {
		writeProblem(w, http.StatusForbidden, controlv1.GuestIpChanged, "your IP changed since this guest trial started; run tnl auth login to continue")
		return
	}
	identity, err := h.publisherIdentities.RegisterGuestPublisherIdentity(r.Context(), guest.ID, ed25519.PublicKey(key), now)
	if errors.Is(err, controlstate.ErrGuestTrialSpent) {
		writeProblem(w, http.StatusForbidden, controlv1.GuestTrialExhausted, "guest demo trial ended; run tnl auth login to continue")
		return
	}
	if err != nil {
		writeControlStateProblem(w, "register guest publisher", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, controlv1.GuestPublisherIdentity{
		ClientId: identity.ID, KeyId: identity.KeyID, GrantId: identity.GrantID,
		TeamId: identity.Scope.TeamID, DomainId: identity.Scope.DomainID, Namespace: identity.Scope.Namespace,
	})
}
