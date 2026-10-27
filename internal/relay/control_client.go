package relay

import (
	"context"
	"errors"
	"net/netip"

	"github.com/tnldotdev/tnl/internal/serviceapi"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// HTTPControlClient adapts the generated private API client to relay control operations.
type HTTPControlClient struct {
	client relayv1.ClientWithResponsesInterface
}

func NewHTTPControlClient(client relayv1.ClientWithResponsesInterface) (*HTTPControlClient, error) {
	if client == nil {
		return nil, errors.New("relay: generated control client is required")
	}
	return &HTTPControlClient{client: client}, nil
}

// NativePeerLegClaimClient is used only after a relay has accepted a connector
// socket and signed the observed source with its current process key.
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

func (c *HTTPControlClient) RegisterRelay(
	ctx context.Context,
	body relayv1.RelayRegistration,
) (relayv1.RelayLease, error) {
	response, err := c.client.RegisterRelayWithResponse(ctx, body)
	if err != nil {
		return relayv1.RelayLease{}, err
	}
	if response == nil {
		return relayv1.RelayLease{}, relayHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return relayv1.RelayLease{}, relayHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

func (c *HTTPControlClient) RenewRelay(
	ctx context.Context,
	relayID relayv1.RelayID,
	body relayv1.RelayRenewal,
) (relayv1.RelayLease, error) {
	response, err := c.client.RenewRelayWithResponse(ctx, relayID, body)
	if err != nil {
		return relayv1.RelayLease{}, err
	}
	if response == nil {
		return relayv1.RelayLease{}, relayHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return relayv1.RelayLease{}, relayHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

func (c *HTTPControlClient) DrainRelay(
	ctx context.Context,
	relayID relayv1.RelayID,
	body relayv1.RelayDrainRequest,
) (relayv1.RelayLease, error) {
	response, err := c.client.DrainRelayWithResponse(ctx, relayID, body)
	if err != nil {
		return relayv1.RelayLease{}, err
	}
	if response == nil {
		return relayv1.RelayLease{}, relayHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return relayv1.RelayLease{}, relayHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

func (c *HTTPControlClient) GetRelayTransportCertificate(
	ctx context.Context,
	relayServiceID relayv1.RelayServiceID,
	params relayv1.GetRelayTransportCertificateParams,
) (relayv1.RelayTransportCertificate, error) {
	response, err := c.client.GetRelayTransportCertificateWithResponse(ctx, relayServiceID, &params)
	if err != nil {
		return relayv1.RelayTransportCertificate{}, err
	}
	if response == nil {
		return relayv1.RelayTransportCertificate{}, relayHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return relayv1.RelayTransportCertificate{}, relayHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

func (c *HTTPControlClient) ClaimPublisherConnection(
	ctx context.Context,
	publisherConnectionID relayv1.PublisherConnectionID,
	body relayv1.PublisherConnectionClaim,
) (relayv1.ClaimedPublisherConnection, error) {
	response, err := c.client.ClaimPublisherConnectionWithResponse(ctx, publisherConnectionID, body)
	if err != nil {
		return relayv1.ClaimedPublisherConnection{}, err
	}
	if response == nil {
		return relayv1.ClaimedPublisherConnection{}, relayHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return relayv1.ClaimedPublisherConnection{}, relayHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

func (c *HTTPControlClient) MarkPublisherConnectionReady(
	ctx context.Context,
	publisherConnectionID relayv1.PublisherConnectionID,
	body relayv1.PublisherConnectionTransition,
) (relayv1.ClaimedPublisherConnection, error) {
	response, err := c.client.MarkPublisherConnectionReadyWithResponse(ctx, publisherConnectionID, body)
	if err != nil {
		return relayv1.ClaimedPublisherConnection{}, err
	}
	if response == nil {
		return relayv1.ClaimedPublisherConnection{}, relayHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return relayv1.ClaimedPublisherConnection{}, relayHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

func (c *HTTPControlClient) DisconnectPublisherConnection(
	ctx context.Context,
	publisherConnectionID relayv1.PublisherConnectionID,
	body relayv1.PublisherConnectionDisconnect,
) (relayv1.ClaimedPublisherConnection, error) {
	response, err := c.client.DisconnectPublisherConnectionWithResponse(ctx, publisherConnectionID, body)
	if err != nil {
		return relayv1.ClaimedPublisherConnection{}, err
	}
	if response == nil {
		return relayv1.ClaimedPublisherConnection{}, relayHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return relayv1.ClaimedPublisherConnection{}, relayHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

func relayHTTPProblem(status int, problem *relayv1.Problem) error {
	result := &serviceapi.ProblemError{Status: status}
	if problem != nil {
		result.Type = problem.Type
		result.Title = problem.Title
		result.Code = string(problem.Code)
		result.Detail = problem.Detail
		result.RequestID = problem.RequestId
	}
	return result
}
