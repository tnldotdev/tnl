package relay

import (
	"context"
	"errors"
	"math"

	"github.com/tnldotdev/tnl/pkg/api/relayv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type PrivateControlClient interface {
	ClaimPrivatePublisherConnection(context.Context, string, relayv1.PrivatePublisherConnectionClaim) (relayv1.PrivatePublisherConnection, error)
	ReadyPrivatePublisherConnection(context.Context, string, relayv1.PrivatePublisherConnectionTransition) (relayv1.PrivatePublisherConnection, error)
	DisconnectPrivatePublisherConnection(context.Context, string, relayv1.PrivatePublisherConnectionTransition) error
}

func (c *Controller) privateClaim(ctx context.Context, ref tunnelv1.PrivatePublisherConnectionRef, credential string) (relayv1.RelayLease, error) {
	lease, err := c.activeLease()
	if err != nil {
		return lease, err
	}
	client, ok := c.client.(PrivateControlClient)
	if !ok || ref.Validate() != nil || ref.RunNumber > math.MaxInt64 || ref.ConnectionAssignmentRevision > math.MaxInt64 || ref.RelayServiceID != lease.RelayServiceId || credential == "" {
		return lease, &tunnelPrivateControlError{code: tunnelv1.Unauthenticated}
	}
	claimed, err := client.ClaimPrivatePublisherConnection(ctx, ref.PublisherConnectionID, relayv1.PrivatePublisherConnectionClaim{
		PrivateServiceId: ref.PrivateServiceID, PrivateRunId: ref.PrivateRunID, RunNumber: int64(ref.RunNumber),
		ConnectionAssignmentRevision: int64(ref.ConnectionAssignmentRevision), Credential: credential,
		RelayId: lease.RelayId, RelayRunId: lease.RelayRunId, RelayLeaseRevision: lease.RelayLeaseRevision})
	if err != nil {
		return lease, c.responseError("claim private publisher connection", err)
	}
	return lease, validatePrivateClaim(ref, claimed)
}

type tunnelPrivateControlError struct{ code tunnelv1.ErrorCode }

func (e *tunnelPrivateControlError) Error() string { return "relay: " + string(e.code) }

func validatePrivateClaim(ref tunnelv1.PrivatePublisherConnectionRef, claimed relayv1.PrivatePublisherConnection) error {
	if claimed.PrivateServiceId != ref.PrivateServiceID || claimed.PrivateRunId != ref.PrivateRunID || claimed.RunNumber != int64(ref.RunNumber) ||
		claimed.PublisherConnectionId != ref.PublisherConnectionID || claimed.ConnectionAssignmentRevision != int64(ref.ConnectionAssignmentRevision) || claimed.RelayServiceId != ref.RelayServiceID {
		return errors.New("relay: control changed private publisher assignment")
	}
	return nil
}

func (c *Controller) privateTransition(ctx context.Context, ref tunnelv1.PrivatePublisherConnectionRef, lease relayv1.RelayLease, disconnect bool) error {
	client, ok := c.client.(PrivateControlClient)
	if !ok {
		return errors.New("relay: private control client is required")
	}
	current := c.Lease()
	if !disconnect && (current.RelayId != lease.RelayId || current.RelayRunId != lease.RelayRunId || current.RelayLeaseRevision != lease.RelayLeaseRevision ||
		current.Draining || !current.LeaseExpiresAt.After(c.now())) {
		return errors.New("relay: private claim lease is stale")
	}
	body := relayv1.PrivatePublisherConnectionTransition{PrivateRunId: ref.PrivateRunID, RunNumber: int64(ref.RunNumber), ConnectionAssignmentRevision: int64(ref.ConnectionAssignmentRevision),
		RelayId: lease.RelayId, RelayRunId: lease.RelayRunId, RelayLeaseRevision: lease.RelayLeaseRevision}
	var claimed relayv1.PrivatePublisherConnection
	var err error
	if disconnect {
		return client.DisconnectPrivatePublisherConnection(ctx, ref.PublisherConnectionID, body)
	}
	claimed, err = client.ReadyPrivatePublisherConnection(ctx, ref.PublisherConnectionID, body)
	if err != nil {
		return c.responseError("transition private publisher connection", err)
	}
	return validatePrivateClaim(ref, claimed)
}

func (c *HTTPControlClient) ClaimPrivatePublisherConnection(ctx context.Context, id string, body relayv1.PrivatePublisherConnectionClaim) (relayv1.PrivatePublisherConnection, error) {
	response, err := c.client.ClaimPrivatePublisherConnectionWithResponse(ctx, id, body)
	if err != nil {
		return relayv1.PrivatePublisherConnection{}, err
	}
	if response == nil {
		return relayv1.PrivatePublisherConnection{}, relayHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return relayv1.PrivatePublisherConnection{}, relayHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}
func (c *HTTPControlClient) ReadyPrivatePublisherConnection(ctx context.Context, id string, body relayv1.PrivatePublisherConnectionTransition) (relayv1.PrivatePublisherConnection, error) {
	response, err := c.client.ReadyPrivatePublisherConnectionWithResponse(ctx, id, body)
	if err != nil {
		return relayv1.PrivatePublisherConnection{}, err
	}
	if response == nil {
		return relayv1.PrivatePublisherConnection{}, relayHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return relayv1.PrivatePublisherConnection{}, relayHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}
func (c *HTTPControlClient) DisconnectPrivatePublisherConnection(ctx context.Context, id string, body relayv1.PrivatePublisherConnectionTransition) error {
	response, err := c.client.DisconnectPrivatePublisherConnectionWithResponse(ctx, id, body)
	if err != nil {
		return err
	}
	if response == nil {
		return relayHTTPProblem(0, nil)
	}
	if response.StatusCode() != 204 {
		return relayHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return nil
}
