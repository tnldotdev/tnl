package relayapi

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
)

type service struct {
	store         Store
	leaseDuration time.Duration
	now           func() time.Time
	report        func(error)
}

func newService(config DirectConfig) (*service, error) {
	if config.Store == nil || config.LeaseDuration <= 0 {
		return nil, errors.New("relayapi: store and lease duration are required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Report == nil {
		config.Report = func(err error) { log.Printf("relay service: %v", err) }
	}
	return &service{
		store: config.Store, leaseDuration: config.LeaseDuration, now: config.Now, report: config.Report,
	}, nil
}

func (s *service) RegisterRelay(ctx context.Context, body relayv1.RelayRegistration) (relayv1.RelayLease, error) {
	if !serviceapi.ValidIdentifiers(
		body.RelayServiceId, body.RelayId, body.RelayRunId, body.RelayAddress,
		body.TlsServerName, body.InternalRelayAddress,
	) {
		return relayv1.RelayLease{}, serviceapi.NewProblemError(
			http.StatusBadRequest, "invalid_request", "Relay registration identifiers are invalid",
		)
	}
	protocolVersion, protocolOK := serviceapi.Positive(body.ProtocolVersion)
	connectionCapacity, connectionOK := serviceapi.Positive(body.ConnectionCapacity)
	streamCapacity, streamOK := serviceapi.Positive(body.StreamCapacity)
	if !protocolOK || !connectionOK || !streamOK {
		return relayv1.RelayLease{}, serviceapi.NewProblemError(
			http.StatusBadRequest, "invalid_request", "Relay protocol and capacities must be positive",
		)
	}
	internalNetworks, ok := canonicalPrefixes(body.InternalNetworks)
	if !ok {
		return relayv1.RelayLease{}, serviceapi.NewProblemError(
			http.StatusBadRequest, "invalid_request",
			"internal_networks must contain at most 64 distinct canonical masked prefixes",
		)
	}
	lease, err := s.store.RegisterRelay(ctx, controlstate.RelayRegistration{
		RelayServiceID: body.RelayServiceId, RelayID: body.RelayId, RelayRunID: body.RelayRunId,
		ProtocolVersion: protocolVersion, RelayAddress: body.RelayAddress, TLSServerName: body.TlsServerName,
		InternalRelayAddress: body.InternalRelayAddress, InternalNetworks: internalNetworks,
		ConnectionCapacity: connectionCapacity, StreamCapacity: streamCapacity,
	}, s.now(), s.leaseDuration)
	if err != nil {
		return relayv1.RelayLease{}, s.storeError(ctx, err)
	}
	return relayLease(lease), nil
}

func (s *service) RenewRelay(
	ctx context.Context,
	relayID relayv1.RelayID,
	body relayv1.RelayRenewal,
) (relayv1.RelayLease, error) {
	if relayID != body.RelayId {
		return relayv1.RelayLease{}, relayPathMismatchError()
	}
	identity, ok := relayLeaseIdentity(body.RelayServiceId, body.RelayId, body.RelayRunId, body.RelayLeaseRevision)
	reportedConnections, connectionsOK := serviceapi.Nonnegative(body.ReportedConnections)
	reportedStreams, streamsOK := serviceapi.Nonnegative(body.ReportedStreams)
	if !ok || !connectionsOK || !streamsOK {
		return relayv1.RelayLease{}, serviceapi.NewProblemError(
			http.StatusBadRequest, "invalid_request", "Relay renewal identity or counters are invalid",
		)
	}
	lease, err := s.store.RenewRelay(ctx, controlstate.RelayRenewal{
		RelayLeaseIdentity: identity, ReportedConnections: reportedConnections, ReportedStreams: reportedStreams,
	}, s.now(), s.leaseDuration)
	if err != nil {
		return relayv1.RelayLease{}, s.storeError(ctx, err)
	}
	return relayLease(lease), nil
}

func (s *service) DrainRelay(
	ctx context.Context,
	relayID relayv1.RelayID,
	body relayv1.RelayDrainRequest,
) (relayv1.RelayLease, error) {
	if relayID != body.RelayId {
		return relayv1.RelayLease{}, relayPathMismatchError()
	}
	identity, ok := relayLeaseIdentity(body.RelayServiceId, body.RelayId, body.RelayRunId, body.RelayLeaseRevision)
	if !ok || !body.Deadline.After(s.now()) {
		return relayv1.RelayLease{}, serviceapi.NewProblemError(
			http.StatusBadRequest, "invalid_request", "Relay drain identity or deadline is invalid",
		)
	}
	lease, err := s.store.BeginRelayDrain(ctx, identity, s.now(), body.Deadline)
	if err != nil {
		return relayv1.RelayLease{}, s.storeError(ctx, err)
	}
	return relayLease(lease), nil
}

func (s *service) GetRelayServiceCertificate(
	ctx context.Context,
	relayServiceID relayv1.RelayServiceID,
	params relayv1.GetRelayServiceCertificateParams,
) (relayv1.RelayServiceCertificate, error) {
	identity, ok := relayLeaseIdentity(relayServiceID, params.RelayId, params.RelayRunId, params.RelayLeaseRevision)
	if !ok {
		return relayv1.RelayServiceCertificate{}, serviceapi.NewProblemError(
			http.StatusBadRequest, "invalid_request", "Relay certificate lease identity is invalid",
		)
	}
	certificate, err := s.store.GetRelayServiceCertificate(ctx, identity, s.now())
	if err != nil {
		return relayv1.RelayServiceCertificate{}, s.storeError(ctx, err)
	}
	return relayv1.RelayServiceCertificate{
		RelayServiceId: certificate.RelayServiceID, TlsServerName: certificate.TLSServerName,
		CertificatePem: certificate.CertificatePEM, PrivateKeyPem: certificate.PrivateKeyPEM,
		NotAfter: certificate.NotAfter,
	}, nil
}

func (s *service) ClaimPublisherConnection(
	ctx context.Context,
	publisherConnectionID relayv1.PublisherConnectionID,
	body relayv1.PublisherConnectionClaim,
) (relayv1.ClaimedPublisherConnection, error) {
	claim, err := publisherConnectionClaim(publisherConnectionID, publisherConnectionFields{
		routeSessionID: body.RouteSessionId, routeID: body.RouteId, routeVersion: body.RouteVersion,
		publisherConnectionID: body.PublisherConnectionId, connectionSlot: body.ConnectionSlot,
		assignmentRevision: body.ConnectionAssignmentRevision, relayServiceID: body.RelayServiceId,
		relayID: body.RelayId, relayRunID: body.RelayRunId, relayLeaseRevision: body.RelayLeaseRevision,
		claimID: body.ClaimId,
	})
	if err != nil {
		return relayv1.ClaimedPublisherConnection{}, err
	}
	digest, err := credentials.ParsePublisherConnectionCredential(
		credentials.PublisherConnectionCredential(body.PublisherConnectionCredential),
	)
	if err != nil {
		return relayv1.ClaimedPublisherConnection{}, serviceapi.NewProblemError(
			http.StatusUnauthorized, "invalid_publisher_connection_credential",
			"Publisher connection credential is invalid",
		)
	}
	claim.CredentialDigest = [32]byte(digest)
	connection, err := s.store.ClaimPublisherConnection(ctx, claim, s.now())
	if err != nil {
		return relayv1.ClaimedPublisherConnection{}, s.storeError(ctx, err)
	}
	return claimedPublisherConnection(connection), nil
}

func (s *service) MarkPublisherConnectionReady(
	ctx context.Context,
	publisherConnectionID relayv1.PublisherConnectionID,
	body relayv1.PublisherConnectionTransition,
) (relayv1.ClaimedPublisherConnection, error) {
	claim, err := publisherConnectionClaim(publisherConnectionID, publisherConnectionFields{
		routeSessionID: body.RouteSessionId, routeID: body.RouteId, routeVersion: body.RouteVersion,
		publisherConnectionID: body.PublisherConnectionId, connectionSlot: body.ConnectionSlot,
		assignmentRevision: body.ConnectionAssignmentRevision, relayServiceID: body.RelayServiceId,
		relayID: body.RelayId, relayRunID: body.RelayRunId, relayLeaseRevision: body.RelayLeaseRevision,
		claimID: body.ClaimId,
	})
	if err != nil {
		return relayv1.ClaimedPublisherConnection{}, err
	}
	connection, err := s.store.MarkPublisherConnectionReady(ctx, claim, s.now())
	if err != nil {
		return relayv1.ClaimedPublisherConnection{}, s.storeError(ctx, err)
	}
	return claimedPublisherConnection(connection), nil
}

func (s *service) DisconnectPublisherConnection(
	ctx context.Context,
	publisherConnectionID relayv1.PublisherConnectionID,
	body relayv1.PublisherConnectionDisconnect,
) (relayv1.ClaimedPublisherConnection, error) {
	claim, err := publisherConnectionClaim(publisherConnectionID, publisherConnectionFields{
		routeSessionID: body.RouteSessionId, routeID: body.RouteId, routeVersion: body.RouteVersion,
		publisherConnectionID: body.PublisherConnectionId, connectionSlot: body.ConnectionSlot,
		assignmentRevision: body.ConnectionAssignmentRevision, relayServiceID: body.RelayServiceId,
		relayID: body.RelayId, relayRunID: body.RelayRunId, relayLeaseRevision: body.RelayLeaseRevision,
		claimID: body.ClaimId,
	})
	if err != nil {
		return relayv1.ClaimedPublisherConnection{}, err
	}
	connection, err := s.store.DisconnectPublisherConnection(ctx, claim, s.now(), body.Unexpected)
	if err != nil {
		return relayv1.ClaimedPublisherConnection{}, s.storeError(ctx, err)
	}
	return claimedPublisherConnection(connection), nil
}

func publisherConnectionClaim(
	publisherConnectionID relayv1.PublisherConnectionID,
	fields publisherConnectionFields,
) (controlstate.PublisherConnectionClaimRequest, error) {
	if publisherConnectionID != fields.publisherConnectionID {
		return controlstate.PublisherConnectionClaimRequest{}, relayPathMismatchError()
	}
	if !serviceapi.ValidIdentifiers(
		fields.routeSessionID, fields.routeID, fields.publisherConnectionID, fields.relayServiceID,
		fields.relayID, fields.relayRunID, fields.claimID,
	) || fields.connectionSlot < 0 || fields.connectionSlot > 1 {
		return controlstate.PublisherConnectionClaimRequest{}, serviceapi.NewProblemError(
			http.StatusBadRequest, "invalid_request", "Publisher connection identity is invalid",
		)
	}
	routeVersion, routeOK := serviceapi.Positive(fields.routeVersion)
	assignmentRevision, assignmentOK := serviceapi.Positive(fields.assignmentRevision)
	leaseRevision, leaseOK := serviceapi.Positive(fields.relayLeaseRevision)
	if !routeOK || !assignmentOK || !leaseOK {
		return controlstate.PublisherConnectionClaimRequest{}, serviceapi.NewProblemError(
			http.StatusBadRequest, "invalid_request", "Publisher connection revisions are invalid",
		)
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
	}, nil
}

func (s *service) storeError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	status, kind, detail := storeProblem(err, s.report)
	return serviceapi.NewProblemError(status, kind, detail)
}

func relayPathMismatchError() error {
	return serviceapi.NewProblemError(
		http.StatusBadRequest, "invalid_request", "Path and request body identifiers do not match",
	)
}
