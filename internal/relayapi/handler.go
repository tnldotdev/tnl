// Package relayapi serves the cluster-authenticated private control API for relays.
package relayapi

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
)

type Store interface {
	RegisterRelay(context.Context, controlstate.RelayRegistration, time.Time, time.Duration) (controlstate.RelayLease, error)
	RenewRelay(context.Context, controlstate.RelayRenewal, time.Time, time.Duration) (controlstate.RelayLease, error)
	BeginRelayDrain(context.Context, controlstate.RelayLeaseIdentity, time.Time, time.Time) (controlstate.RelayLease, error)
	GetRelayServiceCertificate(context.Context, controlstate.RelayLeaseIdentity, time.Time) (controlstate.RelayServiceCertificate, error)
	ClaimPublisherConnection(context.Context, controlstate.PublisherConnectionClaimRequest, time.Time) (controlstate.ClaimedPublisherConnection, error)
	MarkPublisherConnectionReady(context.Context, controlstate.PublisherConnectionClaimRequest, time.Time) (controlstate.ClaimedPublisherConnection, error)
	DisconnectPublisherConnection(context.Context, controlstate.PublisherConnectionClaimRequest, time.Time, bool) (controlstate.ClaimedPublisherConnection, error)
}

type Config struct {
	Store          Store
	ClusterSecrets serviceapi.BearerSecrets
	LeaseDuration  time.Duration
	Now            func() time.Time
	Report         func(error)
}

type handler struct {
	store          Store
	clusterSecrets serviceapi.BearerSecrets
	leaseDuration  time.Duration
	now            func() time.Time
	report         func(error)
	mux            *http.ServeMux
}

// NewHandler constructs the private relay service.
func NewHandler(config Config) (http.Handler, error) {
	if config.Store == nil || !config.ClusterSecrets.Valid() {
		return nil, errors.New("relayapi: store and cluster secrets are required")
	}
	if config.LeaseDuration <= 0 {
		return nil, errors.New("relayapi: relay lease duration must be positive")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Report == nil {
		config.Report = func(err error) { log.Printf("relay service: %v", err) }
	}
	h := &handler{
		store: config.Store, clusterSecrets: config.ClusterSecrets, leaseDuration: config.LeaseDuration,
		now: config.Now, report: config.Report, mux: http.NewServeMux(),
	}
	relayv1.HandlerWithOptions(generatedServer{handler: h}, relayv1.StdHTTPServerOptions{
		BaseRouter: h.mux,
		ErrorHandlerFunc: func(response http.ResponseWriter, _ *http.Request, _ error) {
			serviceapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", "Relay request parameters are invalid")
		},
	})
	h.mux.HandleFunc("/", func(response http.ResponseWriter, _ *http.Request) {
		serviceapi.WriteProblem(response, http.StatusNotFound, "not_found", "Relay service endpoint not found")
	})
	return h, nil
}

func (h *handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	if !h.clusterSecrets.Authenticate(request.Header) {
		response.Header().Set("WWW-Authenticate", "Bearer")
		serviceapi.WriteProblem(response, http.StatusUnauthorized, "unauthenticated", "A valid cluster secret is required")
		return
	}
	h.mux.ServeHTTP(response, request)
}

func (h *handler) registerRelay(response http.ResponseWriter, request *http.Request) {
	var body relayv1.RelayRegistration
	if !serviceapi.DecodeJSON(response, request, &body) {
		return
	}
	if !serviceapi.ValidIdentifiers(
		body.RelayServiceId, body.RelayId, body.RelayRunId, body.RelayAddress,
		body.TlsServerName, body.InternalRelayAddress,
	) {
		serviceapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", "Relay registration identifiers are invalid")
		return
	}
	protocolVersion, protocolOK := serviceapi.Positive(body.ProtocolVersion)
	connectionCapacity, connectionOK := serviceapi.Positive(body.ConnectionCapacity)
	streamCapacity, streamOK := serviceapi.Positive(body.StreamCapacity)
	if !protocolOK || !connectionOK || !streamOK {
		serviceapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", "Relay protocol and capacities must be positive")
		return
	}
	internalNetworks, ok := canonicalPrefixes(body.InternalNetworks)
	if !ok {
		serviceapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", "internal_networks must contain at most 64 distinct canonical masked prefixes")
		return
	}
	lease, err := h.store.RegisterRelay(request.Context(), controlstate.RelayRegistration{
		RelayServiceID: body.RelayServiceId, RelayID: body.RelayId, RelayRunID: body.RelayRunId,
		ProtocolVersion: protocolVersion, RelayAddress: body.RelayAddress, TLSServerName: body.TlsServerName,
		InternalRelayAddress: body.InternalRelayAddress, InternalNetworks: internalNetworks,
		ConnectionCapacity: connectionCapacity, StreamCapacity: streamCapacity,
	}, h.now(), h.leaseDuration)
	if err != nil {
		h.writeStoreError(response, err)
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, relayLease(lease))
}

func (h *handler) renewRelay(response http.ResponseWriter, request *http.Request) {
	var body relayv1.RelayRenewal
	if !serviceapi.DecodeJSON(response, request, &body) ||
		!serviceapi.MatchingPathValue(response, request, "relay_id", body.RelayId) {
		return
	}
	identity, ok := relayLeaseIdentity(body.RelayServiceId, body.RelayId, body.RelayRunId, body.RelayLeaseRevision)
	reportedConnections, connectionsOK := serviceapi.Nonnegative(body.ReportedConnections)
	reportedStreams, streamsOK := serviceapi.Nonnegative(body.ReportedStreams)
	if !ok || !connectionsOK || !streamsOK {
		serviceapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", "Relay renewal identity or counters are invalid")
		return
	}
	lease, err := h.store.RenewRelay(request.Context(), controlstate.RelayRenewal{
		RelayLeaseIdentity: identity, ReportedConnections: reportedConnections, ReportedStreams: reportedStreams,
	}, h.now(), h.leaseDuration)
	if err != nil {
		h.writeStoreError(response, err)
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, relayLease(lease))
}

func (h *handler) drainRelay(response http.ResponseWriter, request *http.Request) {
	var body relayv1.RelayDrainRequest
	if !serviceapi.DecodeJSON(response, request, &body) ||
		!serviceapi.MatchingPathValue(response, request, "relay_id", body.RelayId) {
		return
	}
	identity, ok := relayLeaseIdentity(body.RelayServiceId, body.RelayId, body.RelayRunId, body.RelayLeaseRevision)
	if !ok || !body.Deadline.After(h.now()) {
		serviceapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", "Relay drain identity or deadline is invalid")
		return
	}
	lease, err := h.store.BeginRelayDrain(request.Context(), identity, h.now(), body.Deadline)
	if err != nil {
		h.writeStoreError(response, err)
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, relayLease(lease))
}

func (h *handler) getRelayServiceCertificate(
	response http.ResponseWriter,
	request *http.Request,
	relayServiceID string,
	params relayv1.GetRelayServiceCertificateParams,
) {
	identity, ok := relayLeaseIdentity(relayServiceID, params.RelayId, params.RelayRunId, params.RelayLeaseRevision)
	if !ok {
		serviceapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", "Relay certificate lease identity is invalid")
		return
	}
	certificate, err := h.store.GetRelayServiceCertificate(request.Context(), identity, h.now())
	if err != nil {
		h.writeStoreError(response, err)
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, relayv1.RelayServiceCertificate{
		RelayServiceId: certificate.RelayServiceID, TlsServerName: certificate.TLSServerName,
		CertificatePem: certificate.CertificatePEM, PrivateKeyPem: certificate.PrivateKeyPEM,
		NotAfter: certificate.NotAfter,
	})
}

func (h *handler) claimPublisherConnection(response http.ResponseWriter, request *http.Request) {
	var body relayv1.PublisherConnectionClaim
	if !serviceapi.DecodeJSON(response, request, &body) {
		return
	}
	claim, ok := h.publisherConnectionClaim(response, request, publisherConnectionFields{
		routeSessionID: body.RouteSessionId, routeID: body.RouteId, routeVersion: body.RouteVersion,
		publisherConnectionID: body.PublisherConnectionId, connectionSlot: body.ConnectionSlot,
		assignmentRevision: body.ConnectionAssignmentRevision, relayServiceID: body.RelayServiceId,
		relayID: body.RelayId, relayRunID: body.RelayRunId, relayLeaseRevision: body.RelayLeaseRevision,
		claimID: body.ClaimId,
	})
	if !ok {
		return
	}
	digest, err := credentials.ParsePublisherConnectionCredential(
		credentials.PublisherConnectionCredential(body.PublisherConnectionCredential),
	)
	if err != nil {
		serviceapi.WriteProblem(response, http.StatusUnauthorized, "invalid_publisher_connection_credential", "Publisher connection credential is invalid")
		return
	}
	claim.CredentialDigest = [32]byte(digest)
	connection, err := h.store.ClaimPublisherConnection(request.Context(), claim, h.now())
	if err != nil {
		h.writeStoreError(response, err)
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, claimedPublisherConnection(connection))
}

func (h *handler) markPublisherConnectionReady(response http.ResponseWriter, request *http.Request) {
	var body relayv1.PublisherConnectionTransition
	if !serviceapi.DecodeJSON(response, request, &body) {
		return
	}
	claim, ok := h.publisherConnectionClaim(response, request, publisherConnectionFields{
		routeSessionID: body.RouteSessionId, routeID: body.RouteId, routeVersion: body.RouteVersion,
		publisherConnectionID: body.PublisherConnectionId, connectionSlot: body.ConnectionSlot,
		assignmentRevision: body.ConnectionAssignmentRevision, relayServiceID: body.RelayServiceId,
		relayID: body.RelayId, relayRunID: body.RelayRunId, relayLeaseRevision: body.RelayLeaseRevision,
		claimID: body.ClaimId,
	})
	if !ok {
		return
	}
	connection, err := h.store.MarkPublisherConnectionReady(request.Context(), claim, h.now())
	if err != nil {
		h.writeStoreError(response, err)
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, claimedPublisherConnection(connection))
}

func (h *handler) disconnectPublisherConnection(response http.ResponseWriter, request *http.Request) {
	var body relayv1.PublisherConnectionDisconnect
	if !serviceapi.DecodeJSON(response, request, &body) {
		return
	}
	claim, ok := h.publisherConnectionClaim(response, request, publisherConnectionFields{
		routeSessionID: body.RouteSessionId, routeID: body.RouteId, routeVersion: body.RouteVersion,
		publisherConnectionID: body.PublisherConnectionId, connectionSlot: body.ConnectionSlot,
		assignmentRevision: body.ConnectionAssignmentRevision, relayServiceID: body.RelayServiceId,
		relayID: body.RelayId, relayRunID: body.RelayRunId, relayLeaseRevision: body.RelayLeaseRevision,
		claimID: body.ClaimId,
	})
	if !ok {
		return
	}
	connection, err := h.store.DisconnectPublisherConnection(request.Context(), claim, h.now(), body.Unexpected)
	if err != nil {
		h.writeStoreError(response, err)
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, claimedPublisherConnection(connection))
}

type publisherConnectionFields struct {
	routeSessionID, routeID                      string
	routeVersion                                 int64
	publisherConnectionID                        string
	connectionSlot                               int
	assignmentRevision                           int64
	relayServiceID, relayID, relayRunID, claimID string
	relayLeaseRevision                           int64
}

func (h *handler) publisherConnectionClaim(
	response http.ResponseWriter,
	request *http.Request,
	fields publisherConnectionFields,
) (controlstate.PublisherConnectionClaimRequest, bool) {
	if !serviceapi.MatchingPathValue(response, request, "publisher_connection_id", fields.publisherConnectionID) {
		return controlstate.PublisherConnectionClaimRequest{}, false
	}
	if !serviceapi.ValidIdentifiers(
		fields.routeSessionID, fields.routeID, fields.publisherConnectionID, fields.relayServiceID,
		fields.relayID, fields.relayRunID, fields.claimID,
	) || fields.connectionSlot < 0 || fields.connectionSlot > 1 {
		serviceapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", "Publisher connection identity is invalid")
		return controlstate.PublisherConnectionClaimRequest{}, false
	}
	routeVersion, routeOK := serviceapi.Positive(fields.routeVersion)
	assignmentRevision, assignmentOK := serviceapi.Positive(fields.assignmentRevision)
	leaseRevision, leaseOK := serviceapi.Positive(fields.relayLeaseRevision)
	if !routeOK || !assignmentOK || !leaseOK {
		serviceapi.WriteProblem(response, http.StatusBadRequest, "invalid_request", "Publisher connection revisions are invalid")
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

func (h *handler) writeStoreError(response http.ResponseWriter, err error) {
	status, kind, detail := storeProblem(err, h.report)
	serviceapi.WriteProblem(response, status, kind, detail)
}

// storeProblem is shared by HTTP and standalone adapters. Role controllers see
// API problems, never controlstate error identities.
func storeProblem(err error, report func(error)) (status int, kind, detail string) {
	switch {
	case errors.Is(err, controlstate.ErrRelayRegistrationConflict):
		return http.StatusConflict, "relay_registration_conflict", "The relay identity or service configuration conflicts with live state"
	case errors.Is(err, controlstate.ErrRelayLeaseStale):
		return http.StatusConflict, "relay_lease_stale", "The relay lease is no longer current"
	case errors.Is(err, controlstate.ErrRelayServiceCertificateLeaseStale):
		return http.StatusConflict, "relay_lease_stale", "The relay lease is no longer current"
	case errors.Is(err, controlstate.ErrRelayServiceCertificateNotFound):
		return http.StatusServiceUnavailable, "certificate_unavailable", "Relay service certificate is not ready"
	case errors.Is(err, controlstate.ErrConnectionAssignmentStale), errors.Is(err, controlstate.ErrRouteSessionStale):
		return http.StatusConflict, "stale_connection_assignment", "The publisher connection assignment is no longer current"
	case errors.Is(err, controlstate.ErrPublisherConnectionAlreadyClaimed):
		return http.StatusConflict, "publisher_connection_already_claimed", "The publisher connection is already claimed"
	case errors.Is(err, controlstate.ErrPublisherConnectionCredential), errors.Is(err, credentials.ErrInvalidPublisherConnectionCredential):
		return http.StatusUnauthorized, "invalid_publisher_connection_credential", "Publisher connection credential is invalid"
	case errors.Is(err, controlstate.ErrRelayDraining):
		return http.StatusServiceUnavailable, "relay_draining", "The relay is draining"
	case errors.Is(err, controlstate.ErrRelayConnectionCapacity):
		return http.StatusServiceUnavailable, "relay_connection_capacity_exhausted", "The relay connection capacity is exhausted"
	case errors.Is(err, controlstate.ErrPublisherConnectionRelayService), errors.Is(err, controlstate.ErrPublisherConnectionUnavailable):
		return http.StatusConflict, "publisher_connection_unavailable", "The publisher connection assignment is unavailable to this relay"
	default:
		report(err)
		return http.StatusInternalServerError, "internal", "The relay service request failed"
	}
}

func relayLeaseIdentity(
	relayServiceID, relayID, relayRunID string,
	relayLeaseRevision int64,
) (controlstate.RelayLeaseIdentity, bool) {
	revision, ok := serviceapi.Positive(relayLeaseRevision)
	if !ok || !serviceapi.ValidIdentifiers(relayServiceID, relayID, relayRunID) {
		return controlstate.RelayLeaseIdentity{}, false
	}
	return controlstate.RelayLeaseIdentity{
		RelayServiceID: relayServiceID, RelayID: relayID,
		RelayRunID: relayRunID, RelayLeaseRevision: revision,
	}, true
}

func canonicalPrefixes(values []string) ([]netip.Prefix, bool) {
	if len(values) > 64 {
		return nil, false
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	seen := make(map[netip.Prefix]struct{}, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() {
			return nil, false
		}
		if _, exists := seen[prefix]; exists {
			return nil, false
		}
		seen[prefix] = struct{}{}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, true
}

func relayLease(lease controlstate.RelayLease) relayv1.RelayLease {
	internalNetworks := make([]string, len(lease.InternalNetworks))
	for index, prefix := range lease.InternalNetworks {
		internalNetworks[index] = prefix.String()
	}
	result := relayv1.RelayLease{
		RelayServiceId: lease.RelayServiceID, RelayId: lease.RelayID, RelayRunId: lease.RelayRunID,
		RelayLeaseRevision: int64(lease.RelayLeaseRevision), ProtocolVersion: int64(lease.ProtocolVersion),
		RelayAddress: lease.RelayAddress, TlsServerName: lease.TLSServerName,
		InternalRelayAddress: lease.InternalRelayAddress, InternalNetworks: internalNetworks,
		ConnectionCapacity: int64(lease.ConnectionCapacity), StreamCapacity: int64(lease.StreamCapacity),
		ReportedConnections: int64(lease.ReportedConnections), ReportedStreams: int64(lease.ReportedStreams),
		Draining: lease.Draining, DrainDeadline: lease.DrainDeadline, RegisteredAt: lease.RegisteredAt,
		RenewedAt: lease.RenewedAt, LeaseExpiresAt: lease.LeaseExpiresAt,
	}
	if lease.ObservedAddress != nil {
		value := lease.ObservedAddress.String()
		result.ObservedAddress = &value
	}
	return result
}

func claimedPublisherConnection(connection controlstate.ClaimedPublisherConnection) relayv1.ClaimedPublisherConnection {
	return relayv1.ClaimedPublisherConnection{
		RouteSessionId: connection.RouteSessionID, RouteId: connection.RouteID,
		RouteVersion: int64(connection.RouteVersion), PublisherConnectionId: connection.PublisherConnectionID,
		ConnectionSlot:               connection.ConnectionSlot,
		ConnectionAssignmentRevision: int64(connection.ConnectionAssignmentRevision),
		RelayServiceId:               connection.ConnectionAssignmentIdentity.RelayServiceID,
		RelayId:                      connection.RelayID, RelayRunId: connection.RelayRunID,
		RelayLeaseRevision: int64(connection.RelayLeaseRevision), ClaimId: connection.ClaimID,
		RelayAddress: connection.RelayAddress, TlsServerName: connection.TLSServerName,
		State:                                  relayv1.ClaimedPublisherConnectionState(connection.State),
		PublisherConnectionCredentialExpiresAt: connection.PublisherConnectionCredentialExpiresAt,
		ConnectedAt:                            connection.ConnectedAt, ReadyAt: connection.ReadyAt,
	}
}
