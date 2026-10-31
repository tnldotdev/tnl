package relayv1

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/netip"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// String and GoString keep the recovered key out of routine formatting.
func (NativePeerPairLegClaim) String() string   { return "native peer pair leg claim" }
func (NativePeerPairLegClaim) GoString() string { return "native peer pair leg claim" }

// NewNativePeerPairLegClaimRequest serializes a proof already signed by the
// connector and a source already observed and signed by the accepting relay.
// this helper does not sign or admit a network session.
func NewNativePeerPairLegClaimRequest(lease RelayLease, observedSocketIP netip.Addr, proof tunnelv1.NativePairLegProof, relaySignature []byte) (NativePeerPairLegClaimRequest, error) {
	if !observedSocketIP.IsValid() || observedSocketIP.Zone() != "" ||
		len(relaySignature) != ed25519.SignatureSize || lease.RelayLeaseRevision <= 0 ||
		lease.RelayServiceId != proof.RelayServiceID || lease.RelayId != proof.RelayID ||
		lease.RelayRunId != proof.RelayRunID || uint64(lease.RelayLeaseRevision) != proof.RelayLeaseRevision {
		return NativePeerPairLegClaimRequest{}, errors.New("relay: invalid native peer pair leg claim")
	}
	var frame bytes.Buffer
	if err := tunnelv1.WriteNativePairLegProof(&frame, proof); err != nil {
		return NativePeerPairLegClaimRequest{}, errors.New("relay: invalid native peer pair leg claim")
	}
	return NativePeerPairLegClaimRequest{
		RelayLease: RelayLeaseIdentity{RelayServiceId: lease.RelayServiceId, RelayId: lease.RelayId,
			RelayRunId: lease.RelayRunId, RelayLeaseRevision: lease.RelayLeaseRevision},
		ObservedSourceIp: observedSocketIP.Unmap().String(),
		ProofFrame:       base64.RawURLEncoding.EncodeToString(frame.Bytes()),
		RelaySignature:   base64.RawURLEncoding.EncodeToString(relaySignature),
	}, nil
}
