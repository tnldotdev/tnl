package public

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type GuestPublisherStore interface {
	EnrollGuestPublisher(context.Context, controlstate.GuestCredential, string, ed25519.PublicKey, time.Time) (controlstate.PublisherIdentity, error)
}

func (h *handler) EnrollGuestPublisher(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !h.config.GuestDemoEnabled {
		writeProblem(w, 404, controlv1.NotFound, "resource not found")
		return
	}
	store, ok := h.dependencies.GuestPublishers, h.dependencies.GuestPublishers != nil
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "guest publisher enrollment is unavailable")
		return
	}
	credential, ok := guestRequestCredential(w, r)
	if !ok {
		return
	}
	var b controlv1.EnrollGuestPublisherRequest
	if decodeJSON(w, r, &b) != nil || !opaqueid.Valid(b.ServiceId, opaqueid.ServicePrefix) {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid guest enrollment")
		return
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(b.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid Ed25519 public key")
		return
	}
	p, err := store.EnrollGuestPublisher(r.Context(), credential, b.ServiceId, key, time.Now())
	if err != nil {
		guestProblem(r.Context(), w, "enroll guest publisher", err)
		return
	}
	writeJSON(w, 200, controlv1.PublisherEnrollmentResult{ClientId: p.ID, KeyId: p.KeyID, GrantId: p.GrantID,
		GuestId: p.Scope.GuestID, TeamId: p.Scope.TeamID, Kind: controlv1.PublisherEnrollmentResultKind(p.Scope.Kind),
		ServiceId: &p.Scope.ServiceID, ExpiresAt: p.ExpiresAt})
}
