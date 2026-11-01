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
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type connectorPeerLegStore interface {
	ClaimConnectorPeerPairLeg(context.Context, controlstate.RelayLeaseIdentity, netip.Addr, tunnelv1.ConnectorPairLegProof, []byte, time.Time) (controlstate.ConnectorPeerPairLegClaim, error)
}

// connectorLegProof reads exactly one bounded tunnel frame from the opaque HTTP
// field; the protocol owns proof fields and validation.
func connectorLegProof(encoded string) (tunnelv1.ConnectorPairLegProof, bool) {
	if encoded == "" || len(encoded) > base64.RawURLEncoding.EncodedLen(tunnelv1.MaxConnectorPairLegProofBytes+4) {
		return tunnelv1.ConnectorPairLegProof{}, false
	}
	frame, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(frame) > tunnelv1.MaxConnectorPairLegProofBytes+4 || base64.RawURLEncoding.EncodeToString(frame) != encoded {
		return tunnelv1.ConnectorPairLegProof{}, false
	}
	reader := bytes.NewReader(frame)
	proof, err := tunnelv1.ReadConnectorPairLegProof(reader)
	return proof, err == nil && reader.Len() == 0
}

func (s *service) ClaimConnectorPeerPairLeg(ctx context.Context, pairID string, slot int, body relayv1.ConnectorPeerPairLegClaimRequest) (relayv1.ConnectorPeerPairLegClaim, error) {
	invalid := func() (relayv1.ConnectorPeerPairLegClaim, error) {
		return relayv1.ConnectorPeerPairLegClaim{}, serviceapi.NewProblemError(http.StatusBadRequest, "invalid_request", "connector peer pair leg claim is invalid")
	}
	proof, valid := connectorLegProof(body.ProofFrame)
	lease, leaseOK := relayLeaseIdentity(body.RelayLease.RelayServiceId, body.RelayLease.RelayId,
		body.RelayLease.RelayRunId, body.RelayLease.RelayLeaseRevision)
	source, sourceErr := netip.ParseAddr(body.ObservedSourceIp)
	signature, signatureErr := base64.RawURLEncoding.Strict().DecodeString(body.RelaySignature)
	if !opaqueid.Valid(pairID, "cpp_") || (slot != 0 && slot != 1) || !valid || !leaseOK ||
		proof.PairID != pairID || proof.ConnectionSlot != slot ||
		proof.RelayServiceID != lease.RelayServiceID || proof.RelayID != lease.RelayID ||
		proof.RelayRunID != lease.RelayRunID || proof.RelayLeaseRevision != lease.RelayLeaseRevision ||
		sourceErr != nil || source.Zone() != "" || signatureErr != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != body.RelaySignature {
		return invalid()
	}
	store, ok := s.store.(connectorPeerLegStore)
	if !ok {
		return relayv1.ConnectorPeerPairLegClaim{}, serviceapi.NewProblemError(http.StatusServiceUnavailable, "publisher_connection_unavailable", "connector peer pair claim is unavailable")
	}
	claim, err := store.ClaimConnectorPeerPairLeg(ctx, lease, source.Unmap(), proof, signature, s.now())
	if err != nil {
		if ctx.Err() != nil {
			return relayv1.ConnectorPeerPairLegClaim{}, context.Cause(ctx)
		}
		if errors.Is(err, controlstate.ErrServiceAccess) || errors.Is(err, controlstate.ErrVisitorPermission) || errors.Is(err, controlstate.ErrWorkloadDenied) {
			return relayv1.ConnectorPeerPairLegClaim{}, serviceapi.NewProblemError(http.StatusConflict, "stale_connection_assignment", "connector peer pair leg is no longer authorized")
		}
		// the operator adapter emits authored text and safe fields, retaining the
		// provider cause for classification rather than printing it to the caller.
		s.report(failure.Wrap("claim connector peer pair leg", failure.ServerAPIInternal, err))
		return relayv1.ConnectorPeerPairLegClaim{}, serviceapi.NewProblemError(http.StatusInternalServerError, "internal", "connector peer pair claim failed")
	}
	return relayv1.ConnectorPeerPairLegClaim{PairId: claim.PairID, DeliveryId: base64.RawURLEncoding.EncodeToString(claim.DeliveryID[:]), DeliveryGeneration: claim.DeliveryGeneration,
		ConnectionSlot: claim.ConnectionSlot, Key: claim.Key, SourceIp: claim.SourceIP.String(), ObservedAt: claim.ObservedAt, ExpiresAt: claim.ExpiresAt}, nil
}

func (h *handler) claimConnectorPeerPairLeg(w http.ResponseWriter, r *http.Request, pairID string, slot int) {
	var body relayv1.ConnectorPeerPairLegClaimRequest
	r.Body = http.MaxBytesReader(w, r.Body, int64(base64.RawURLEncoding.EncodedLen(tunnelv1.MaxConnectorPairLegProofBytes+4)+2048))
	if !serviceapi.DecodeJSON(w, r, &body) {
		return
	}
	claim, err := h.service.ClaimConnectorPeerPairLeg(r.Context(), pairID, slot, body)
	if h.writeServiceError(w, r, err) {
		return
	}
	serviceapi.WriteJSON(w, http.StatusOK, claim)
}

// ClaimConnectorPeerPairLegFromAcceptedSocket executes the same checked operation
// in standalone.
// the caller must sign the socket-observed source with its current relay key.
func (c *DirectClient) ClaimConnectorPeerPairLegFromAcceptedSocket(ctx context.Context, lease relayv1.RelayLease, observedSocketIP netip.Addr, proof tunnelv1.ConnectorPairLegProof, relaySignature []byte) (relayv1.ConnectorPeerPairLegClaim, error) {
	body, err := relayv1.NewConnectorPeerPairLegClaimRequest(lease, observedSocketIP, proof, relaySignature)
	if err != nil {
		return relayv1.ConnectorPeerPairLegClaim{}, err
	}
	return c.service.ClaimConnectorPeerPairLeg(ctx, proof.PairID, proof.ConnectionSlot, body)
}
