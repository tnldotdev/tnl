package relay

import (
	"context"
	"errors"
	"math"
	"net/netip"

	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func (c *Controller) claimServiceConnection(ctx context.Context, ref tunnelv1.ServicePublisherConnectionRef, credential string, source netip.Addr) (relayv1.RelayLease, error) {
	lease, err := c.activeLease()
	if err != nil {
		return lease, err
	}
	if ref.Validate() != nil || ref.RunNumber > math.MaxInt64 || ref.ConnectionAssignmentRevision > math.MaxInt64 || ref.RelayServiceID != lease.RelayServiceId || credential == "" ||
		!source.IsValid() || source.IsUnspecified() || source.Zone() != "" {
		return lease, &serviceControlError{code: tunnelv1.Unauthenticated}
	}
	claimed, err := c.client.ClaimServicePublisherConnection(ctx, ref.PublisherConnectionID, relayv1.ServicePublisherConnectionClaim{
		ServiceId: ref.ServiceID, ServiceRunId: ref.ServiceRunID, RunNumber: int64(ref.RunNumber),
		ConnectionAssignmentRevision: int64(ref.ConnectionAssignmentRevision), Credential: credential,
		ObservedSourceIp: source.Unmap().String(),
		RelayId:          lease.RelayId, RelayRunId: lease.RelayRunId, RelayLeaseRevision: lease.RelayLeaseRevision})
	if err != nil {
		return lease, c.responseError("claim service publisher connection", err)
	}
	return lease, validateServiceClaim(ref, claimed)
}

type serviceControlError struct{ code tunnelv1.ErrorCode }

func (e *serviceControlError) Error() string { return "relay: " + string(e.code) }

func validateServiceClaim(ref tunnelv1.ServicePublisherConnectionRef, claimed relayv1.ServicePublisherConnection) error {
	if serviceClaimRef(claimed, ref.ConnectionSlot) != ref {
		return errors.New("relay: control changed service publisher assignment")
	}
	return nil
}

func (c *Controller) transitionServiceConnection(ctx context.Context, ref tunnelv1.ServicePublisherConnectionRef, lease relayv1.RelayLease, disconnect, unexpected bool) error {
	current := c.Lease()
	if !disconnect && (current.RelayServiceId != lease.RelayServiceId || current.RelayId != lease.RelayId || current.RelayRunId != lease.RelayRunId || current.RelayLeaseRevision != lease.RelayLeaseRevision ||
		current.Draining || !current.LeaseExpiresAt.After(c.now())) {
		return errors.New("relay: service claim lease is stale")
	}
	body := relayv1.ServicePublisherConnectionTransition{ServiceRunId: ref.ServiceRunID, RunNumber: int64(ref.RunNumber), ConnectionAssignmentRevision: int64(ref.ConnectionAssignmentRevision),
		RelayId: lease.RelayId, RelayRunId: lease.RelayRunId, RelayLeaseRevision: lease.RelayLeaseRevision}
	var claimed relayv1.ServicePublisherConnection
	var err error
	if disconnect {
		body.Unexpected = new(unexpected)
		if err := c.client.DisconnectServicePublisherConnection(ctx, ref.PublisherConnectionID, body); err != nil {
			return c.responseError("disconnect service publisher connection", err)
		}
		return nil
	}
	claimed, err = c.client.ReadyServicePublisherConnection(ctx, ref.PublisherConnectionID, body)
	if err != nil {
		return c.responseError("ready service publisher connection", err)
	}
	return validateServiceClaim(ref, claimed)
}

func (c *HTTPControlClient) ClaimServicePublisherConnection(ctx context.Context, id string, body relayv1.ServicePublisherConnectionClaim) (relayv1.ServicePublisherConnection, error) {
	response, err := c.client.ClaimServicePublisherConnectionWithResponse(ctx, id, body)
	if err != nil {
		return relayv1.ServicePublisherConnection{}, err
	}
	if response == nil {
		return relayv1.ServicePublisherConnection{}, relayHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return relayv1.ServicePublisherConnection{}, relayHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}
func (c *HTTPControlClient) ReadyServicePublisherConnection(ctx context.Context, id string, body relayv1.ServicePublisherConnectionTransition) (relayv1.ServicePublisherConnection, error) {
	response, err := c.client.ReadyServicePublisherConnectionWithResponse(ctx, id, body)
	if err != nil {
		return relayv1.ServicePublisherConnection{}, err
	}
	if response == nil {
		return relayv1.ServicePublisherConnection{}, relayHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return relayv1.ServicePublisherConnection{}, relayHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}
func (c *HTTPControlClient) DisconnectServicePublisherConnection(ctx context.Context, id string, body relayv1.ServicePublisherConnectionTransition) error {
	response, err := c.client.DisconnectServicePublisherConnectionWithResponse(ctx, id, body)
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
