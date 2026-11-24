package relay

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	serverhttp "github.com/tnldotdev/tnl/internal/serverhttp"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
)

type serviceConnectionStore interface {
	ClaimServicePublisherConnection(context.Context, string, string, string, int64, int64, string, netip.Addr, controlstate.RelayLeaseIdentity, time.Time) (controlstate.ServicePublisherConnection, error)
	ReadyServicePublisherConnection(context.Context, string, string, int64, int64, controlstate.RelayLeaseIdentity, time.Time) (controlstate.ServicePublisherConnection, error)
	DisconnectServicePublisherConnection(context.Context, string, string, int64, int64, controlstate.RelayLeaseIdentity, time.Time, bool) (controlstate.ServicePublisherConnection, error)
}

func privateRelayIdentity(id, run string, revision int64) controlstate.RelayLeaseIdentity {
	return controlstate.RelayLeaseIdentity{RelayID: id, RelayRunID: run, RelayLeaseRevision: uint64(revision)}
}

func privateRelayResponse(row controlstate.ServicePublisherConnection) relayv1.ServicePublisherConnection {
	return relayv1.ServicePublisherConnection{ServiceId: row.ServiceID, ServiceRunId: row.RunID,
		PublisherConnectionId: row.ConnectionID, RunNumber: row.RunNumber,
		ConnectionAssignmentRevision: row.Revision, RelayServiceId: row.RelayServiceID}
}

// the authenticated relay supplies its accepted publisher peer, not its control
// connection's source or any visitor address. standalone uses the same check.
func servicePublisherSource(value string) (netip.Addr, error) {
	source, err := netip.ParseAddr(value)
	if err != nil || !source.IsValid() || source.IsUnspecified() || source.Zone() != "" || source.Unmap().String() != value {
		return netip.Addr{}, errors.New("invalid publisher source")
	}
	return source, nil
}

func (h *handler) claimServicePublisherConnection(w http.ResponseWriter, r *http.Request, id relayv1.Identifier) {
	var body relayv1.ServicePublisherConnectionClaim
	if !serverhttp.DecodeJSON(w, r, &body) {
		return
	}
	row, err := h.service.ClaimServicePublisherConnection(r.Context(), id, body)
	if h.writeServiceError(w, r, err) {
		return
	}
	serverhttp.WriteJSON(w, 200, row)
}

func (h *handler) readyServicePublisherConnection(w http.ResponseWriter, r *http.Request, id relayv1.Identifier) {
	var body relayv1.ServicePublisherConnectionTransition
	if !serverhttp.DecodeJSON(w, r, &body) {
		return
	}
	row, err := h.service.ReadyServicePublisherConnection(r.Context(), id, body)
	if h.writeServiceError(w, r, err) {
		return
	}
	serverhttp.WriteJSON(w, http.StatusOK, row)
}

func (h *handler) disconnectServicePublisherConnection(w http.ResponseWriter, r *http.Request, id relayv1.Identifier) {
	var body relayv1.ServicePublisherConnectionTransition
	if !serverhttp.DecodeJSON(w, r, &body) {
		return
	}
	if h.writeServiceError(w, r, h.service.DisconnectServicePublisherConnection(r.Context(), id, body)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// http and standalone share validation and error classification, not just the
// database mutation. controllers never receive raw state error identities.
func (s *service) ClaimServicePublisherConnection(ctx context.Context, id string, body relayv1.ServicePublisherConnectionClaim) (relayv1.ServicePublisherConnection, error) {
	if !allowedProcess(ctx, body.RelayId) {
		return relayv1.ServicePublisherConnection{}, slotDenied()
	}
	source, err := servicePublisherSource(body.ObservedSourceIp)
	if err != nil || !opaqueid.Valid(id, opaqueid.PublisherConnectionPrefix) || !opaqueid.Valid(body.ServiceId, opaqueid.ServicePrefix) ||
		!opaqueid.Valid(body.ServiceRunId, opaqueid.ServiceRunPrefix) || body.RunNumber <= 0 || body.ConnectionAssignmentRevision <= 0 || body.RelayLeaseRevision <= 0 ||
		!serverhttp.ValidIdentifiers(body.RelayId, body.RelayRunId) {
		return relayv1.ServicePublisherConnection{}, serverhttp.NewProblemError(http.StatusBadRequest, "invalid_request", "publisher connection claim is invalid")
	}
	if _, err := credentials.ParsePublisherConnectionCredential(credentials.PublisherConnectionCredential(body.Credential)); err != nil {
		return relayv1.ServicePublisherConnection{}, serverhttp.NewProblemError(http.StatusUnauthorized, "invalid_publisher_connection_credential", "Publisher connection credential is invalid")
	}
	row, err := s.store.ClaimServicePublisherConnection(ctx, id, body.ServiceId, body.ServiceRunId, body.RunNumber, body.ConnectionAssignmentRevision, body.Credential,
		source, privateRelayIdentity(body.RelayId, body.RelayRunId, body.RelayLeaseRevision), s.now())
	if err != nil {
		return relayv1.ServicePublisherConnection{}, s.storeError(ctx, err)
	}
	return privateRelayResponse(row), nil
}

func (s *service) ReadyServicePublisherConnection(ctx context.Context, id string, body relayv1.ServicePublisherConnectionTransition) (relayv1.ServicePublisherConnection, error) {
	row, err := s.servicePublisherTransition(ctx, id, body, false)
	return privateRelayResponse(row), err
}

func (s *service) DisconnectServicePublisherConnection(ctx context.Context, id string, body relayv1.ServicePublisherConnectionTransition) error {
	_, err := s.servicePublisherTransition(ctx, id, body, true)
	return err
}

func (s *service) servicePublisherTransition(ctx context.Context, id string, body relayv1.ServicePublisherConnectionTransition, disconnect bool) (controlstate.ServicePublisherConnection, error) {
	if !allowedProcess(ctx, body.RelayId) {
		return controlstate.ServicePublisherConnection{}, slotDenied()
	}
	if !opaqueid.Valid(id, opaqueid.PublisherConnectionPrefix) || !opaqueid.Valid(body.ServiceRunId, opaqueid.ServiceRunPrefix) ||
		body.RunNumber <= 0 || body.ConnectionAssignmentRevision <= 0 || body.RelayLeaseRevision <= 0 ||
		!serverhttp.ValidIdentifiers(body.RelayId, body.RelayRunId) || disconnect != (body.Unexpected != nil) {
		return controlstate.ServicePublisherConnection{}, serverhttp.NewProblemError(http.StatusBadRequest, "invalid_request", "publisher connection transition is invalid")
	}
	lease := privateRelayIdentity(body.RelayId, body.RelayRunId, body.RelayLeaseRevision)
	var row controlstate.ServicePublisherConnection
	var err error
	if disconnect {
		row, err = s.store.DisconnectServicePublisherConnection(ctx, id, body.ServiceRunId, body.RunNumber, body.ConnectionAssignmentRevision, lease, s.now(), *body.Unexpected)
	} else {
		row, err = s.store.ReadyServicePublisherConnection(ctx, id, body.ServiceRunId, body.RunNumber, body.ConnectionAssignmentRevision, lease, s.now())
	}
	if err != nil {
		return controlstate.ServicePublisherConnection{}, s.storeError(ctx, err)
	}
	return row, nil
}
