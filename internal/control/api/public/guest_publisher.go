package controlapi

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type GuestPublisherStore interface {
	GuestTrialByAccessToken(context.Context, credentials.AccessToken) (controlstate.GuestTrial, error)
	EnrollGuestPublisher(context.Context, string, string, string, ed25519.PublicKey, time.Time) (controlstate.PublisherIdentity, error)
}

func (h *handler) EnrollGuestPublisher(w http.ResponseWriter, r *http.Request) {
	if !h.config.GuestDemoEnabled {
		writeProblem(w, 404, controlv1.NotFound, "resource not found")
		return
	}
	store, ok := h.store.(GuestPublisherStore)
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "guest publisher enrollment is unavailable")
		return
	}
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	var b controlv1.EnrollGuestPublisherRequest
	if decodeJSON(w, r, &b) != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid guest enrollment")
		return
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(b.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid Ed25519 public key")
		return
	}
	trial, err := store.GuestTrialByAccessToken(r.Context(), credentials.AccessToken(token))
	if err != nil {
		writeBearerProblem(w)
		return
	}
	p, err := store.EnrollGuestPublisher(r.Context(), trial.ID, b.PublicUrlId, publisherRequestSource(r), key, time.Now())
	if err != nil {
		publisherProblem(w, "enroll guest publisher", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, controlv1.GuestPublisherIdentity{ClientId: p.ID, KeyId: p.KeyID, GrantId: p.GrantID, TeamId: p.Scope.TeamID, PublicUrlId: p.Scope.PublicURLID})
}
