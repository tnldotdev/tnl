package authorityapi

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"mime"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func (h *handler) RedeemPublisherEnrollment(w http.ResponseWriter, r *http.Request) {
	if h.publisher == nil {
		writeAuthenticationUnavailable(w, "redeem publisher enrollment", nil)
		return
	}
	var body authorityv1.RedeemPublisherEnrollmentRequest
	if err := decodeJSON(w, r, &body); err != nil {
		writeProblem(w, http.StatusBadRequest, authorityv1.InvalidRequest, "invalid enrollment request")
		return
	}
	key, err := base64.RawURLEncoding.DecodeString(body.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		writeProblem(w, http.StatusBadRequest, authorityv1.InvalidRequest, "invalid publisher public key")
		return
	}
	identity, err := h.publisher.RedeemPublisherEnrollment(r.Context(), body.EnrollmentKey, ed25519.PublicKey(key), time.Now().UTC())
	if errors.Is(err, controlstate.ErrPublisherEnrollment) || errors.Is(err, controlstate.ErrPublisherIdentity) {
		writeProblem(w, http.StatusUnauthorized, authorityv1.Unauthenticated, "publisher enrollment is invalid or expired")
		return
	}
	if err != nil {
		writeAuthenticationUnavailable(w, "redeem publisher enrollment", err)
		return
	}
	result := authorityv1.PublisherEnrollmentResult{
		ClientId: identity.ID, KeyId: identity.KeyID, GrantId: identity.GrantID,
		TeamId: identity.Scope.TeamID, Kind: authorityv1.PublisherEnrollmentResultKind(identity.Scope.Kind),
	}
	if identity.Scope.PublicURLID != "" {
		result.PublicUrlId = &identity.Scope.PublicURLID
	} else {
		result.Namespace = &identity.Scope.Namespace
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, result)
}

func (h *handler) RotatePublisherKey(w http.ResponseWriter, r *http.Request) {
	if h.publisher == nil || h.config.ControlURL == "" {
		writeAuthenticationUnavailable(w, "rotate publisher key", nil)
		return
	}
	var body authorityv1.RotatePublisherKeyRequest
	if err := decodeJSON(w, r, &body); err != nil {
		writeProblem(w, http.StatusBadRequest, authorityv1.InvalidRequest, "invalid publisher key rotation")
		return
	}
	public, err := base64.RawURLEncoding.DecodeString(body.PublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		writeProblem(w, http.StatusBadRequest, authorityv1.InvalidRequest, "invalid replacement publisher key")
		return
	}
	access, err := credentials.Bearer(r.Header)
	if err != nil {
		writeBearerProblem(w)
		return
	}
	err = h.publisher.RotatePublisherKey(r.Context(), access, body.KeyId,
		h.config.ControlURL+"/v1/publisher/keys/rotate", ed25519.PublicKey(public), body.Proof, time.Now().UTC())
	if errors.Is(err, controlstate.ErrPublisherIdentity) {
		writeBearerProblem(w)
		return
	}
	if err != nil {
		writeAuthenticationUnavailable(w, "rotate publisher key", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) ExchangePublisherAssertion(w http.ResponseWriter, r *http.Request) {
	if h.publisher == nil || h.config.ControlURL == "" {
		writeAuthenticationUnavailable(w, "exchange publisher assertion", nil)
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" {
		writeProblem(w, http.StatusBadRequest, authorityv1.InvalidRequest, "publisher token request needs form data")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil || len(r.PostForm) != 5 ||
		r.PostForm.Get("grant_type") != publisheridentity.GrantType ||
		r.PostForm.Get("client_assertion_type") != publisheridentity.AssertionType {
		writeProblem(w, http.StatusBadRequest, authorityv1.InvalidRequest, "invalid publisher token request")
		return
	}
	for _, values := range r.PostForm {
		if len(values) != 1 || values[0] == "" {
			writeProblem(w, http.StatusBadRequest, authorityv1.InvalidRequest, "invalid publisher token request")
			return
		}
	}
	now := time.Now().UTC()
	access, err := h.publisher.ExchangePublisherAssertion(r.Context(), r.PostForm.Get("client_id"),
		r.PostForm.Get("scope"), h.config.ControlURL+"/v1/publisher/token", r.PostForm.Get("client_assertion"), now)
	if errors.Is(err, controlstate.ErrPublisherIdentity) {
		writeProblem(w, http.StatusUnauthorized, authorityv1.Unauthenticated, "publisher client authentication failed")
		return
	}
	if err != nil {
		writeAuthenticationUnavailable(w, "exchange publisher assertion", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, authorityv1.PublisherTokenResponse{
		AccessToken: access.Token, ExpiresIn: int(access.Until.Sub(now).Seconds()),
		Scope: access.GrantID, TokenType: authorityv1.PublisherTokenResponseTokenType("Bearer"),
	})
}
