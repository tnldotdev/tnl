package relay

import (
	"context"
	"net/netip"

	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// ConnectorPeerLegClaimClient carries an accepted socket's process-signed source.
// it neither accepts sockets nor installs a connector delivery.
type ConnectorPeerLegClaimClient interface {
	ClaimConnectorPeerPairLegFromAcceptedSocket(context.Context, relayv1.RelayLease, netip.Addr, tunnelv1.ConnectorPairLegProof, []byte) (relayv1.ConnectorPeerPairLegClaim, error)
}

var _ ConnectorPeerLegClaimClient = (*HTTPControlClient)(nil)

func (c *HTTPControlClient) ClaimConnectorPeerPairLegFromAcceptedSocket(ctx context.Context, lease relayv1.RelayLease, observedSocketIP netip.Addr, proof tunnelv1.ConnectorPairLegProof, relaySignature []byte) (relayv1.ConnectorPeerPairLegClaim, error) {
	body, err := relayv1.NewConnectorPeerPairLegClaimRequest(lease, observedSocketIP, proof, relaySignature)
	if err != nil {
		return relayv1.ConnectorPeerPairLegClaim{}, err
	}
	response, err := c.client.ClaimConnectorPeerPairLegWithResponse(ctx, proof.PairID, proof.ConnectionSlot, body)
	if err != nil {
		return relayv1.ConnectorPeerPairLegClaim{}, err
	}
	if response == nil {
		return relayv1.ConnectorPeerPairLegClaim{}, relayHTTPProblem(0, nil)
	}
	defer clear(response.Body)
	if response.JSON200 == nil {
		return relayv1.ConnectorPeerPairLegClaim{}, relayHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}
