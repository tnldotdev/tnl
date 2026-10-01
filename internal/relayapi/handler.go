// Package relayapi serves control's private API for relay processes.
package relayapi

import (
	"context"
	"errors"
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
	GetRelayTransportCertificate(context.Context, controlstate.RelayLeaseIdentity, time.Time) (controlstate.RelayTransportCertificate, error)
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
	service        *service
	clusterSecrets serviceapi.BearerSecrets
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
	service, err := newService(DirectConfig{
		Store: config.Store, LeaseDuration: config.LeaseDuration, Now: config.Now, Report: config.Report,
	})
	if err != nil {
		return nil, err
	}
	h := &handler{
		service: service, clusterSecrets: config.ClusterSecrets, mux: http.NewServeMux(),
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
	if !serviceapi.AuthenticateClusterRequest(response, request, h.clusterSecrets) {
		return
	}
	h.mux.ServeHTTP(response, request)
}

// MatchedPattern is safe to call before authentication; it never returns an ID.
func (h *handler) MatchedPattern(request *http.Request) string {
	_, pattern := h.mux.Handler(request)
	return pattern
}

func (h *handler) registerRelay(response http.ResponseWriter, request *http.Request) {
	var body relayv1.RelayRegistration
	if !serviceapi.DecodeJSON(response, request, &body) {
		return
	}
	lease, err := h.service.RegisterRelay(request.Context(), body)
	if h.writeServiceError(response, request, err) {
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, lease)
}

func (h *handler) renewRelay(response http.ResponseWriter, request *http.Request, relayID relayv1.RelayID) {
	var body relayv1.RelayRenewal
	if !serviceapi.DecodeJSON(response, request, &body) {
		return
	}
	lease, err := h.service.RenewRelay(request.Context(), relayID, body)
	if h.writeServiceError(response, request, err) {
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, lease)
}

func (h *handler) drainRelay(response http.ResponseWriter, request *http.Request, relayID relayv1.RelayID) {
	var body relayv1.RelayDrainRequest
	if !serviceapi.DecodeJSON(response, request, &body) {
		return
	}
	lease, err := h.service.DrainRelay(request.Context(), relayID, body)
	if h.writeServiceError(response, request, err) {
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, lease)
}

func (h *handler) getRelayTransportCertificate(
	response http.ResponseWriter,
	request *http.Request,
	relayServiceID string,
	params relayv1.GetRelayTransportCertificateParams,
) {
	certificate, err := h.service.GetRelayTransportCertificate(request.Context(), relayServiceID, params)
	if h.writeServiceError(response, request, err) {
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, certificate)
}

func (h *handler) claimPublisherConnection(
	response http.ResponseWriter,
	request *http.Request,
	publisherConnectionID relayv1.PublisherConnectionID,
) {
	var body relayv1.PublisherConnectionClaim
	if !serviceapi.DecodeJSON(response, request, &body) {
		return
	}
	connection, err := h.service.ClaimPublisherConnection(request.Context(), publisherConnectionID, body)
	if h.writeServiceError(response, request, err) {
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, connection)
}

func (h *handler) markPublisherConnectionReady(
	response http.ResponseWriter,
	request *http.Request,
	publisherConnectionID relayv1.PublisherConnectionID,
) {
	var body relayv1.PublisherConnectionTransition
	if !serviceapi.DecodeJSON(response, request, &body) {
		return
	}
	connection, err := h.service.MarkPublisherConnectionReady(request.Context(), publisherConnectionID, body)
	if h.writeServiceError(response, request, err) {
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, connection)
}

func (h *handler) disconnectPublisherConnection(
	response http.ResponseWriter,
	request *http.Request,
	publisherConnectionID relayv1.PublisherConnectionID,
) {
	var body relayv1.PublisherConnectionDisconnect
	if !serviceapi.DecodeJSON(response, request, &body) {
		return
	}
	connection, err := h.service.DisconnectPublisherConnection(request.Context(), publisherConnectionID, body)
	if h.writeServiceError(response, request, err) {
		return
	}
	serviceapi.WriteJSON(response, http.StatusOK, connection)
}

type publisherConnectionFields struct {
	publishRunID, publicURLID                    string
	publishRunNumber                             int64
	publisherConnectionID                        string
	connectionSlot                               int
	assignmentRevision                           int64
	relayServiceID, relayID, relayRunID, claimID string
	relayLeaseRevision                           int64
}

func (h *handler) writeServiceError(response http.ResponseWriter, request *http.Request, err error) bool {
	return serviceapi.WriteServiceError(response, request, err, h.service.report, "The relay service request failed")
}

// storeProblem is shared by HTTP and standalone adapters. role controllers see
// API problems, never controlstate error identities.
func storeProblem(err error, report func(error)) (status int, kind, detail string) {
	switch {
	case errors.Is(err, controlstate.ErrRelayRegistrationConflict):
		return http.StatusConflict, "relay_registration_conflict", "The relay identity or service configuration conflicts with live state"
	case errors.Is(err, controlstate.ErrRelayLeaseStale):
		return http.StatusConflict, "relay_lease_stale", "The relay lease is no longer current"
	case errors.Is(err, controlstate.ErrRelayTransportCertificateLeaseStale):
		return http.StatusConflict, "relay_lease_stale", "The relay lease is no longer current"
	case errors.Is(err, controlstate.ErrRelayTransportCertificateNotFound):
		return http.StatusServiceUnavailable, "certificate_unavailable", "The relay transport certificate is not ready"
	case errors.Is(err, controlstate.ErrConnectionAssignmentStale), errors.Is(err, controlstate.ErrPublishRunStale):
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
		PublishRunId: connection.PublishRunID, PublicUrlId: connection.PublicURLID,
		PublishRunNumber: int64(connection.PublishRunNumber), PublisherConnectionId: connection.PublisherConnectionID,
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
