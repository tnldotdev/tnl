package relay

import (
	"context"
	"net/netip"

	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// NativePeerLegClaimClient carries an accepted socket's process-signed source.
// it neither accepts sockets nor installs a native delivery.
type NativePeerLegClaimClient interface {
	ClaimNativePeerPairLegFromAcceptedSocket(context.Context, relayv1.RelayLease, netip.Addr, tunnelv1.NativePairLegProof, []byte) (relayv1.NativePeerPairLegClaim, error)
}

var _ NativePeerLegClaimClient = (*HTTPControlClient)(nil)

func (c *HTTPControlClient) ClaimNativePeerPairLegFromAcceptedSocket(ctx context.Context, lease relayv1.RelayLease, observedSocketIP netip.Addr, proof tunnelv1.NativePairLegProof, relaySignature []byte) (relayv1.NativePeerPairLegClaim, error) {
	body, err := relayv1.NewNativePeerPairLegClaimRequest(lease, observedSocketIP, proof, relaySignature)
	if err != nil {
		return relayv1.NativePeerPairLegClaim{}, err
	}
	response, err := c.client.ClaimNativePeerPairLegWithResponse(ctx, proof.PairID, proof.ConnectionSlot, body)
	if err != nil {
		return relayv1.NativePeerPairLegClaim{}, err
	}
	if response == nil {
		return relayv1.NativePeerPairLegClaim{}, relayHTTPProblem(0, nil)
	}
	defer clear(response.Body)
	if response.JSON200 == nil {
		return relayv1.NativePeerPairLegClaim{}, relayHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}
