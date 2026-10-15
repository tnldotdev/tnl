package authorityapi

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

type PublisherIdentityStore interface {
	RedeemPublisherEnrollment(context.Context, string, ed25519.PublicKey, time.Time) (controlstate.PublisherIdentity, error)
	ExchangePublisherAssertion(context.Context, string, string, string, string, string, time.Time) (controlstate.PublisherAccess, error)
	RotatePublisherKey(context.Context, string, string, string, string, ed25519.PublicKey, string, string, time.Time) error
}

func publisherSource(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return ""
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return ""
	}
	ip = ip.Unmap()
	return netip.PrefixFrom(ip, ip.BitLen()).String()
}

func publisherPublicKey(value string) (ed25519.PublicKey, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, controlstate.ErrPublisherIdentity
	}
	return ed25519.PublicKey(b), nil
}

func PublisherEnrollmentResponse(p controlstate.PublisherIdentity) authorityv1.PublisherEnrollmentResult {
	r := authorityv1.PublisherEnrollmentResult{ClientId: p.ID, KeyId: p.KeyID, GrantId: p.GrantID, TeamId: p.Scope.TeamID, Kind: authorityv1.PublisherEnrollmentResultKind(p.Scope.Kind)}
	if p.Scope.PublicURLID != "" {
		r.PublicUrlId = &p.Scope.PublicURLID
	}
	if p.Scope.DomainID != "" {
		r.DomainId = &p.Scope.DomainID
	}
	if p.Scope.Namespace != "" {
		r.Namespace = &p.Scope.Namespace
	}
	return r
}

func publisherAuthError(w http.ResponseWriter, operation string, err error) {
	if errors.Is(err, controlstate.ErrPublisherIdentity) || errors.Is(err, controlstate.ErrPublisherEnrollment) || errors.Is(err, pgx.ErrNoRows) {
		writeBearerProblem(w)
		return
	}
	writeAuthenticationUnavailable(w, operation, err)
}

func (h *handler) RedeemPublisherEnrollment(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	store, ok := h.store.(PublisherIdentityStore)
	if !ok {
		writeAuthenticationUnavailable(w, "enroll publisher", nil)
		return
	}
	var body authorityv1.RedeemPublisherEnrollmentRequest
	if err := decodeJSON(w, r, &body); err != nil {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid publisher enrollment")
		return
	}
	key, err := publisherPublicKey(body.PublicKey)
	if err != nil {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid Ed25519 public key")
		return
	}
	p, err := store.RedeemPublisherEnrollment(r.Context(), body.EnrollmentKey, key, time.Now())
	if err != nil {
		publisherAuthError(w, "enroll publisher", err)
		return
	}
	writeJSON(w, 200, PublisherEnrollmentResponse(p))
}

func (h *handler) ExchangePublisherAssertion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	store, ok := h.store.(PublisherIdentityStore)
	if !ok || h.config.ControlURL == "" {
		writeAuthenticationUnavailable(w, "exchange publisher assertion", nil)
		return
	}
	var b authorityv1.PublisherTokenRequest
	if decodeJSON(w, r, &b) != nil || string(b.GrantType) != publisheridentity.GrantType || string(b.ClientAssertionType) != publisheridentity.AssertionType {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid publisher token request")
		return
	}
	now := time.Now()
	access, err := store.ExchangePublisherAssertion(r.Context(), b.ClientId, b.GrantId, h.config.ControlURL+"/v1/publisher-token", b.ClientAssertion, publisherSource(r), now)
	if err != nil {
		publisherAuthError(w, "exchange publisher assertion", err)
		return
	}
	writeJSON(w, 200, authorityv1.PublisherTokenResponse{AccessToken: access.Token, TokenType: "Bearer", GrantId: b.GrantId, ExpiresIn: max(1, int(access.Until.Sub(now).Seconds()))})
}

func (h *handler) RotatePublisherKey(w http.ResponseWriter, r *http.Request) {
	store, ok := h.store.(PublisherIdentityStore)
	if !ok || h.config.ControlURL == "" {
		writeAuthenticationUnavailable(w, "rotate publisher key", nil)
		return
	}
	token, err := credentials.Bearer(r.Header)
	if err != nil {
		writeBearerProblem(w)
		return
	}
	var b authorityv1.RotatePublisherKeyRequest
	if decodeJSON(w, r, &b) != nil {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid key rotation")
		return
	}
	key, err := publisherPublicKey(b.PublicKey)
	if err != nil {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid Ed25519 public key")
		return
	}
	if err := store.RotatePublisherKey(r.Context(), token, publisherSource(r), b.KeyId, h.config.ControlURL+"/v1/publisher-keys/rotate", key, b.Proof, b.CurrentProof, time.Now()); err != nil {
		publisherAuthError(w, "rotate publisher key", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
