package relay

import (
	"context"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
)

type serviceConnectionStore interface {
	ClaimServicePublisherConnection(context.Context, string, string, string, int64, int64, string, controlstate.RelayLeaseIdentity, time.Time) (controlstate.ServicePublisherConnection, error)
	ReadyServicePublisherConnection(context.Context, string, string, int64, int64, controlstate.RelayLeaseIdentity, time.Time) (controlstate.ServicePublisherConnection, error)
	DisconnectServicePublisherConnection(context.Context, string, string, int64, int64, controlstate.RelayLeaseIdentity, time.Time) (controlstate.ServicePublisherConnection, error)
}

func (h *handler) serviceConnections(w http.ResponseWriter) (serviceConnectionStore, bool) {
	store, ok := h.service.store.(serviceConnectionStore)
	if !ok {
		serviceapi.WriteProblem(w, 503, "unavailable", "Private publisher connection state is unavailable")
	}
	return store, ok
}

func privateRelayIdentity(id, run string, revision int64) controlstate.RelayLeaseIdentity {
	return controlstate.RelayLeaseIdentity{RelayID: id, RelayRunID: run, RelayLeaseRevision: uint64(revision)}
}

func privateRelayProblem(h *handler, w http.ResponseWriter, r *http.Request, err error) bool {
	if errors.Is(err, controlstate.ErrServiceAccess) {
		serviceapi.WriteProblem(w, 409, "stale_connection_assignment", "Private publisher connection is not current")
		return true
	}
	return h.writeServiceError(w, r, err)
}

func privateRelayResponse(row controlstate.ServicePublisherConnection) relayv1.ServicePublisherConnection {
	return relayv1.ServicePublisherConnection{ServiceId: row.ServiceID, ServiceRunId: row.RunID,
		PublisherConnectionId: row.ConnectionID, RunNumber: row.RunNumber,
		ConnectionAssignmentRevision: row.Revision, RelayServiceId: row.RelayServiceID}
}

func (h *handler) claimServicePublisherConnection(w http.ResponseWriter, r *http.Request, id relayv1.Identifier) {
	var body relayv1.ServicePublisherConnectionClaim
	if !serviceapi.DecodeJSON(w, r, &body) {
		return
	}
	if !opaqueid.Valid(id, opaqueid.PublisherConnectionPrefix) || !opaqueid.Valid(body.ServiceId, opaqueid.ServicePrefix) ||
		!opaqueid.Valid(body.ServiceRunId, opaqueid.ServiceRunPrefix) || body.RunNumber <= 0 || body.ConnectionAssignmentRevision <= 0 || body.RelayLeaseRevision <= 0 {
		serviceapi.WriteProblem(w, 400, "invalid_request", "Private connection claim is invalid")
		return
	}
	store, ok := h.serviceConnections(w)
	if !ok {
		return
	}
	row, err := store.ClaimServicePublisherConnection(r.Context(), id, body.ServiceId, body.ServiceRunId,
		body.RunNumber, body.ConnectionAssignmentRevision, body.Credential,
		privateRelayIdentity(body.RelayId, body.RelayRunId, body.RelayLeaseRevision), h.service.now())
	if privateRelayProblem(h, w, r, err) {
		return
	}
	serviceapi.WriteJSON(w, 200, privateRelayResponse(row))
}

func (h *handler) readyServicePublisherConnection(w http.ResponseWriter, r *http.Request, id relayv1.Identifier) {
	h.servicePublisherTransition(w, r, id, false)
}

func (h *handler) disconnectServicePublisherConnection(w http.ResponseWriter, r *http.Request, id relayv1.Identifier) {
	h.servicePublisherTransition(w, r, id, true)
}

func (h *handler) servicePublisherTransition(w http.ResponseWriter, r *http.Request, id string, disconnect bool) {
	var body relayv1.ServicePublisherConnectionTransition
	if !serviceapi.DecodeJSON(w, r, &body) {
		return
	}
	if !opaqueid.Valid(id, opaqueid.PublisherConnectionPrefix) || !opaqueid.Valid(body.ServiceRunId, opaqueid.ServiceRunPrefix) ||
		body.RunNumber <= 0 || body.ConnectionAssignmentRevision <= 0 || body.RelayLeaseRevision <= 0 {
		serviceapi.WriteProblem(w, 400, "invalid_request", "Private connection transition is invalid")
		return
	}
	store, ok := h.serviceConnections(w)
	if !ok {
		return
	}
	lease := privateRelayIdentity(body.RelayId, body.RelayRunId, body.RelayLeaseRevision)
	var row controlstate.ServicePublisherConnection
	var err error
	if disconnect {
		row, err = store.DisconnectServicePublisherConnection(r.Context(), id, body.ServiceRunId,
			body.RunNumber, body.ConnectionAssignmentRevision, lease, h.service.now())
	} else {
		row, err = store.ReadyServicePublisherConnection(r.Context(), id, body.ServiceRunId,
			body.RunNumber, body.ConnectionAssignmentRevision, lease, h.service.now())
	}
	if privateRelayProblem(h, w, r, err) {
		return
	}
	if disconnect {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	serviceapi.WriteJSON(w, 200, privateRelayResponse(row))
}

func (c *DirectClient) ClaimServicePublisherConnection(ctx context.Context, id string, body relayv1.ServicePublisherConnectionClaim) (relayv1.ServicePublisherConnection, error) {
	store, ok := c.store.(serviceConnectionStore)
	if !ok {
		return relayv1.ServicePublisherConnection{}, errors.New("private publisher connection state is unavailable")
	}
	row, err := store.ClaimServicePublisherConnection(ctx, id, body.ServiceId, body.ServiceRunId, body.RunNumber, body.ConnectionAssignmentRevision, body.Credential,
		privateRelayIdentity(body.RelayId, body.RelayRunId, body.RelayLeaseRevision), c.now())
	return privateRelayResponse(row), err
}

func (c *DirectClient) ReadyServicePublisherConnection(ctx context.Context, id string, body relayv1.ServicePublisherConnectionTransition) (relayv1.ServicePublisherConnection, error) {
	store, ok := c.store.(serviceConnectionStore)
	if !ok {
		return relayv1.ServicePublisherConnection{}, errors.New("private publisher connection state is unavailable")
	}
	row, err := store.ReadyServicePublisherConnection(ctx, id, body.ServiceRunId, body.RunNumber, body.ConnectionAssignmentRevision,
		privateRelayIdentity(body.RelayId, body.RelayRunId, body.RelayLeaseRevision), c.now())
	return privateRelayResponse(row), err
}

func (c *DirectClient) DisconnectServicePublisherConnection(ctx context.Context, id string, body relayv1.ServicePublisherConnectionTransition) error {
	store, ok := c.store.(serviceConnectionStore)
	if !ok {
		return errors.New("private publisher connection state is unavailable")
	}
	_, err := store.DisconnectServicePublisherConnection(ctx, id, body.ServiceRunId, body.RunNumber, body.ConnectionAssignmentRevision,
		privateRelayIdentity(body.RelayId, body.RelayRunId, body.RelayLeaseRevision), c.now())
	return err
}
