package relayapi

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
)

// DirectClient implements controller operations inside standalone. It trusts
// internally constructed request identities and ignores path IDs/request editors;
// it does not perform HTTP authentication or expose raw response bodies. Domain
// failures use the HTTP problem/status contract; caller cancellation is a Go error.
type DirectClient struct {
	store         Store
	leaseDuration time.Duration
	now           func() time.Time
	report        func(error)
}

func NewDirectClient(store Store, leaseDuration time.Duration) (*DirectClient, error) {
	if store == nil || leaseDuration <= 0 {
		return nil, errors.New("relayapi: direct store and lease duration are required")
	}
	return &DirectClient{store: store, leaseDuration: leaseDuration, now: time.Now,
		report: func(err error) { log.Printf("relay service: %v", err) }}, nil
}

func (c *DirectClient) problem(err error) relayv1.Problem {
	status, kind, detail := storeProblem(err, c.report)
	return relayv1.Problem{Status: status, Type: "https://tnl.dev/problems/" + kind,
		Title: strings.ReplaceAll(kind, "_", " "), Detail: detail}
}

func (c *DirectClient) RegisterRelayWithResponse(
	ctx context.Context,
	body relayv1.RegisterRelayJSONRequestBody,
	_ ...relayv1.RequestEditorFn,
) (*relayv1.RegisterRelayResponse, error) {
	protocolVersion, protocolOK := serviceapi.Positive(body.ProtocolVersion)
	connectionCapacity, connectionOK := serviceapi.Positive(body.ConnectionCapacity)
	streamCapacity, streamOK := serviceapi.Positive(body.StreamCapacity)
	internalNetworks, networksOK := canonicalPrefixes(body.InternalNetworks)
	if !protocolOK || !connectionOK || !streamOK || !networksOK {
		return nil, errors.New("relayapi: direct registration is invalid")
	}
	lease, err := c.store.RegisterRelay(ctx, controlstate.RelayRegistration{
		RelayServiceID: body.RelayServiceId, RelayID: body.RelayId, RelayRunID: body.RelayRunId,
		ProtocolVersion: protocolVersion, RelayAddress: body.RelayAddress, TLSServerName: body.TlsServerName,
		InternalRelayAddress: body.InternalRelayAddress, InternalNetworks: internalNetworks,
		ConnectionCapacity: connectionCapacity, StreamCapacity: streamCapacity,
	}, c.now(), c.leaseDuration)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		problem := c.problem(err)
		return &relayv1.RegisterRelayResponse{HTTPResponse: serviceapi.StatusResponse(problem.Status), ApplicationproblemJSONDefault: &problem}, nil
	}
	result := relayLease(lease)
	return &relayv1.RegisterRelayResponse{HTTPResponse: serviceapi.StatusResponse(http.StatusOK), JSON200: &result}, nil
}

func (c *DirectClient) RenewRelayWithResponse(
	ctx context.Context,
	_ relayv1.RelayID,
	body relayv1.RenewRelayJSONRequestBody,
	_ ...relayv1.RequestEditorFn,
) (*relayv1.RenewRelayResponse, error) {
	identity, ok := relayLeaseIdentity(body.RelayServiceId, body.RelayId, body.RelayRunId, body.RelayLeaseRevision)
	reportedConnections, connectionsOK := serviceapi.Nonnegative(body.ReportedConnections)
	reportedStreams, streamsOK := serviceapi.Nonnegative(body.ReportedStreams)
	if !ok || !connectionsOK || !streamsOK {
		return nil, errors.New("relayapi: direct renewal is invalid")
	}
	lease, err := c.store.RenewRelay(ctx, controlstate.RelayRenewal{
		RelayLeaseIdentity: identity, ReportedConnections: reportedConnections, ReportedStreams: reportedStreams,
	}, c.now(), c.leaseDuration)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		problem := c.problem(err)
		return &relayv1.RenewRelayResponse{HTTPResponse: serviceapi.StatusResponse(problem.Status), ApplicationproblemJSONDefault: &problem}, nil
	}
	result := relayLease(lease)
	return &relayv1.RenewRelayResponse{HTTPResponse: serviceapi.StatusResponse(http.StatusOK), JSON200: &result}, nil
}

func (c *DirectClient) DrainRelayWithResponse(
	ctx context.Context,
	_ relayv1.RelayID,
	body relayv1.DrainRelayJSONRequestBody,
	_ ...relayv1.RequestEditorFn,
) (*relayv1.DrainRelayResponse, error) {
	identity, ok := relayLeaseIdentity(body.RelayServiceId, body.RelayId, body.RelayRunId, body.RelayLeaseRevision)
	if !ok {
		return nil, errors.New("relayapi: direct drain is invalid")
	}
	lease, err := c.store.BeginRelayDrain(ctx, identity, c.now(), body.Deadline)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		problem := c.problem(err)
		return &relayv1.DrainRelayResponse{HTTPResponse: serviceapi.StatusResponse(problem.Status), ApplicationproblemJSONDefault: &problem}, nil
	}
	result := relayLease(lease)
	return &relayv1.DrainRelayResponse{HTTPResponse: serviceapi.StatusResponse(http.StatusOK), JSON200: &result}, nil
}

func (c *DirectClient) GetRelayServiceCertificateWithResponse(
	ctx context.Context,
	relayServiceID relayv1.RelayServiceID,
	params *relayv1.GetRelayServiceCertificateParams,
	_ ...relayv1.RequestEditorFn,
) (*relayv1.GetRelayServiceCertificateResponse, error) {
	if params == nil {
		return nil, errors.New("relayapi: direct certificate parameters are required")
	}
	identity, ok := relayLeaseIdentity(relayServiceID, params.RelayId, params.RelayRunId, params.RelayLeaseRevision)
	if !ok {
		return nil, errors.New("relayapi: direct certificate identity is invalid")
	}
	certificate, err := c.store.GetRelayServiceCertificate(ctx, identity, c.now())
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		problem := c.problem(err)
		return &relayv1.GetRelayServiceCertificateResponse{HTTPResponse: serviceapi.StatusResponse(problem.Status), ApplicationproblemJSONDefault: &problem}, nil
	}
	result := relayv1.RelayServiceCertificate{
		RelayServiceId: certificate.RelayServiceID, TlsServerName: certificate.TLSServerName,
		CertificatePem: certificate.CertificatePEM, PrivateKeyPem: certificate.PrivateKeyPEM,
		NotAfter: certificate.NotAfter,
	}
	return &relayv1.GetRelayServiceCertificateResponse{HTTPResponse: serviceapi.StatusResponse(http.StatusOK), JSON200: &result}, nil
}

func (c *DirectClient) ClaimPublisherConnectionWithResponse(
	ctx context.Context,
	_ relayv1.PublisherConnectionID,
	body relayv1.ClaimPublisherConnectionJSONRequestBody,
	_ ...relayv1.RequestEditorFn,
) (*relayv1.ClaimPublisherConnectionResponse, error) {
	claim, ok := directPublisherConnectionClaim(publisherConnectionFields{
		routeSessionID: body.RouteSessionId, routeID: body.RouteId, routeVersion: body.RouteVersion,
		publisherConnectionID: body.PublisherConnectionId, connectionSlot: body.ConnectionSlot,
		assignmentRevision: body.ConnectionAssignmentRevision, relayServiceID: body.RelayServiceId,
		relayID: body.RelayId, relayRunID: body.RelayRunId, relayLeaseRevision: body.RelayLeaseRevision,
		claimID: body.ClaimId,
	})
	if !ok {
		return nil, errors.New("relayapi: direct publisher connection claim is invalid")
	}
	digest, err := credentials.ParsePublisherConnectionCredential(
		credentials.PublisherConnectionCredential(body.PublisherConnectionCredential),
	)
	if err != nil {
		problem := c.problem(err)
		return &relayv1.ClaimPublisherConnectionResponse{HTTPResponse: serviceapi.StatusResponse(problem.Status), ApplicationproblemJSONDefault: &problem}, nil
	}
	claim.CredentialDigest = [32]byte(digest)
	connection, err := c.store.ClaimPublisherConnection(ctx, claim, c.now())
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		problem := c.problem(err)
		return &relayv1.ClaimPublisherConnectionResponse{HTTPResponse: serviceapi.StatusResponse(problem.Status), ApplicationproblemJSONDefault: &problem}, nil
	}
	result := claimedPublisherConnection(connection)
	return &relayv1.ClaimPublisherConnectionResponse{HTTPResponse: serviceapi.StatusResponse(http.StatusOK), JSON200: &result}, nil
}

func (c *DirectClient) MarkPublisherConnectionReadyWithResponse(
	ctx context.Context,
	_ relayv1.PublisherConnectionID,
	body relayv1.MarkPublisherConnectionReadyJSONRequestBody,
	_ ...relayv1.RequestEditorFn,
) (*relayv1.MarkPublisherConnectionReadyResponse, error) {
	claim, ok := directPublisherConnectionClaim(publisherConnectionFields{
		routeSessionID: body.RouteSessionId, routeID: body.RouteId, routeVersion: body.RouteVersion,
		publisherConnectionID: body.PublisherConnectionId, connectionSlot: body.ConnectionSlot,
		assignmentRevision: body.ConnectionAssignmentRevision, relayServiceID: body.RelayServiceId,
		relayID: body.RelayId, relayRunID: body.RelayRunId, relayLeaseRevision: body.RelayLeaseRevision,
		claimID: body.ClaimId,
	})
	if !ok {
		return nil, errors.New("relayapi: direct publisher connection transition is invalid")
	}
	connection, err := c.store.MarkPublisherConnectionReady(ctx, claim, c.now())
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		problem := c.problem(err)
		return &relayv1.MarkPublisherConnectionReadyResponse{HTTPResponse: serviceapi.StatusResponse(problem.Status), ApplicationproblemJSONDefault: &problem}, nil
	}
	result := claimedPublisherConnection(connection)
	return &relayv1.MarkPublisherConnectionReadyResponse{HTTPResponse: serviceapi.StatusResponse(http.StatusOK), JSON200: &result}, nil
}

func (c *DirectClient) DisconnectPublisherConnectionWithResponse(
	ctx context.Context,
	_ relayv1.PublisherConnectionID,
	body relayv1.DisconnectPublisherConnectionJSONRequestBody,
	_ ...relayv1.RequestEditorFn,
) (*relayv1.DisconnectPublisherConnectionResponse, error) {
	claim, ok := directPublisherConnectionClaim(publisherConnectionFields{
		routeSessionID: body.RouteSessionId, routeID: body.RouteId, routeVersion: body.RouteVersion,
		publisherConnectionID: body.PublisherConnectionId, connectionSlot: body.ConnectionSlot,
		assignmentRevision: body.ConnectionAssignmentRevision, relayServiceID: body.RelayServiceId,
		relayID: body.RelayId, relayRunID: body.RelayRunId, relayLeaseRevision: body.RelayLeaseRevision,
		claimID: body.ClaimId,
	})
	if !ok {
		return nil, errors.New("relayapi: direct publisher connection disconnect is invalid")
	}
	connection, err := c.store.DisconnectPublisherConnection(ctx, claim, c.now(), body.Unexpected)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		problem := c.problem(err)
		return &relayv1.DisconnectPublisherConnectionResponse{HTTPResponse: serviceapi.StatusResponse(problem.Status), ApplicationproblemJSONDefault: &problem}, nil
	}
	result := claimedPublisherConnection(connection)
	return &relayv1.DisconnectPublisherConnectionResponse{HTTPResponse: serviceapi.StatusResponse(http.StatusOK), JSON200: &result}, nil
}

func directPublisherConnectionClaim(fields publisherConnectionFields) (controlstate.PublisherConnectionClaimRequest, bool) {
	routeVersion, routeOK := serviceapi.Positive(fields.routeVersion)
	assignmentRevision, assignmentOK := serviceapi.Positive(fields.assignmentRevision)
	leaseRevision, leaseOK := serviceapi.Positive(fields.relayLeaseRevision)
	if !routeOK || !assignmentOK || !leaseOK || fields.connectionSlot < 0 || fields.connectionSlot > 1 {
		return controlstate.PublisherConnectionClaimRequest{}, false
	}
	return controlstate.PublisherConnectionClaimRequest{
		ConnectionAssignmentIdentity: controlstate.ConnectionAssignmentIdentity{
			RouteSessionID: fields.routeSessionID, RouteID: fields.routeID, RouteVersion: routeVersion,
			ConnectionSlot: fields.connectionSlot, PublisherConnectionID: fields.publisherConnectionID,
			ConnectionAssignmentRevision: assignmentRevision, RelayServiceID: fields.relayServiceID,
		},
		RelayLeaseIdentity: controlstate.RelayLeaseIdentity{
			RelayServiceID: fields.relayServiceID, RelayID: fields.relayID,
			RelayRunID: fields.relayRunID, RelayLeaseRevision: leaseRevision,
		},
		ClaimID: fields.claimID,
	}, true
}
