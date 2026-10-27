package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"net/netip"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type nativePeerLegStore interface {
	ClaimNativePeerPairLeg(context.Context, controlstate.RelayLeaseIdentity, netip.Addr, tunnelv1.NativePairLegProof, []byte, time.Time) (controlstate.NativePeerPairLegClaim, error)
}

// nativeLegProof reads exactly one bounded tunnel frame from the opaque HTTP
// field; the protocol owns proof fields and validation.
func nativeLegProof(encoded string) (tunnelv1.NativePairLegProof, bool) {
	if encoded == "" || len(encoded) > base64.RawURLEncoding.EncodedLen(tunnelv1.MaxNativePairLegProofBytes+4) {
		return tunnelv1.NativePairLegProof{}, false
	}
	frame, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(frame) > tunnelv1.MaxNativePairLegProofBytes+4 || base64.RawURLEncoding.EncodeToString(frame) != encoded {
		return tunnelv1.NativePairLegProof{}, false
	}
	reader := bytes.NewReader(frame)
	proof, err := tunnelv1.ReadNativePairLegProof(reader)
	return proof, err == nil && reader.Len() == 0
}

func (s *service) ClaimNativePeerPairLeg(ctx context.Context, pairID string, slot int, body relayv1.NativePeerPairLegClaimRequest) (relayv1.NativePeerPairLegClaim, error) {
	invalid := func() (relayv1.NativePeerPairLegClaim, error) {
		return relayv1.NativePeerPairLegClaim{}, serviceapi.NewProblemError(http.StatusBadRequest, "invalid_request", "native peer pair leg claim is invalid")
	}
	proof, valid := nativeLegProof(body.ProofFrame)
	lease, leaseOK := relayLeaseIdentity(body.RelayLease.RelayServiceId, body.RelayLease.RelayId,
		body.RelayLease.RelayRunId, body.RelayLease.RelayLeaseRevision)
	source, sourceErr := netip.ParseAddr(body.ObservedSourceIp)
	signature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(body.RelaySignature)
	if !opaqueid.Valid(pairID, "npp_") || (slot != 0 && slot != 1) || !valid || !leaseOK ||
		proof.PairID != pairID || proof.ConnectionSlot != slot ||
		proof.RelayServiceID != lease.RelayServiceID || proof.RelayID != lease.RelayID ||
		proof.RelayRunID != lease.RelayRunID || proof.RelayLeaseRevision != lease.RelayLeaseRevision ||
		sourceErr != nil || source.Zone() != "" || signatureErr != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != body.RelaySignature {
		return invalid()
	}
	store, ok := s.store.(nativePeerLegStore)
	if !ok {
		return relayv1.NativePeerPairLegClaim{}, serviceapi.NewProblemError(http.StatusServiceUnavailable, "publisher_connection_unavailable", "native peer pair claim is unavailable")
	}
	claim, err := store.ClaimNativePeerPairLeg(ctx, lease, source.Unmap(), proof, signature, s.now())
	if err != nil {
		if errors.Is(err, controlstate.ErrServiceAccess) || errors.Is(err, controlstate.ErrVisitorPermission) || errors.Is(err, controlstate.ErrWorkloadDenied) {
			return relayv1.NativePeerPairLegClaim{}, serviceapi.NewProblemError(http.StatusConflict, "stale_connection_assignment", "native peer pair leg is no longer authorized")
		}
		// never report an error containing the proof, socket IP, or recovered key.
		s.report(errors.New("native peer pair leg claim failed"))
		return relayv1.NativePeerPairLegClaim{}, serviceapi.NewProblemError(http.StatusInternalServerError, "internal", "native peer pair claim failed")
	}
	return relayv1.NativePeerPairLegClaim{PairId: claim.PairID, DeliveryId: base64.RawURLEncoding.EncodeToString(claim.DeliveryID[:]), DeliveryGeneration: claim.DeliveryGeneration,
		ConnectionSlot: claim.ConnectionSlot, Key: claim.Key, SourceIp: claim.SourceIP.String(), ObservedAt: claim.ObservedAt, ExpiresAt: claim.ExpiresAt}, nil
}

func (h *handler) claimNativePeerPairLeg(w http.ResponseWriter, r *http.Request, pairID string, slot int) {
	var body relayv1.NativePeerPairLegClaimRequest
	r.Body = http.MaxBytesReader(w, r.Body, int64(base64.RawURLEncoding.EncodedLen(tunnelv1.MaxNativePairLegProofBytes+4)+2048))
	if !serviceapi.DecodeJSON(w, r, &body) {
		return
	}
	claim, err := h.service.ClaimNativePeerPairLeg(r.Context(), pairID, slot, body)
	if h.writeServiceError(w, r, err) {
		return
	}
	serviceapi.WriteJSON(w, http.StatusOK, claim)
}

// ClaimNativePeerPairLegFromAcceptedSocket executes the same checked operation
// in standalone.
// the caller must sign the socket-observed source with its current relay key.
func (c *DirectClient) ClaimNativePeerPairLegFromAcceptedSocket(ctx context.Context, lease relayv1.RelayLease, observedSocketIP netip.Addr, proof tunnelv1.NativePairLegProof, relaySignature []byte) (relayv1.NativePeerPairLegClaim, error) {
	body, err := relayv1.NewNativePeerPairLegClaimRequest(lease, observedSocketIP, proof, relaySignature)
	if err != nil {
		return relayv1.NativePeerPairLegClaim{}, err
	}
	return c.service.ClaimNativePeerPairLeg(ctx, proof.PairID, proof.ConnectionSlot, body)
}
