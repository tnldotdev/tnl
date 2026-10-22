package relayapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
)

type privateConnectionStore interface {
	ClaimPrivatePublisherConnection(context.Context, string, string, string, int64, int64, string, controlstate.RelayLeaseIdentity, time.Time) (controlstate.PrivatePublisherConnection, error)
	ReadyPrivatePublisherConnection(context.Context, string, string, int64, int64, controlstate.RelayLeaseIdentity, time.Time) (controlstate.PrivatePublisherConnection, error)
	DisconnectPrivatePublisherConnection(context.Context, string, string, int64, int64, controlstate.RelayLeaseIdentity, time.Time) (controlstate.PrivatePublisherConnection, error)
}

func (h *handler) privateConnections(w http.ResponseWriter) (privateConnectionStore, bool) {
	store, ok := h.service.store.(privateConnectionStore)
	if !ok {
		serviceapi.WriteProblem(w, 503, "unavailable", "Private publisher connection state is unavailable")
	}
	return store, ok
}

func privateRelayIdentity(id, run string, revision int64) controlstate.RelayLeaseIdentity {
	return controlstate.RelayLeaseIdentity{RelayID: id, RelayRunID: run, RelayLeaseRevision: uint64(revision)}
}

func privateRelayProblem(h *handler, w http.ResponseWriter, r *http.Request, err error) bool {
	if errors.Is(err, controlstate.ErrPrivateServiceAccess) {
		serviceapi.WriteProblem(w, 409, "stale_connection_assignment", "Private publisher connection is not current")
		return true
	}
	return h.writeServiceError(w, r, err)
}

func privateRelayResponse(row controlstate.PrivatePublisherConnection) relayv1.PrivatePublisherConnection {
	return relayv1.PrivatePublisherConnection{PrivateServiceId: row.ServiceID, PrivateRunId: row.RunID,
		PublisherConnectionId: row.ConnectionID, RunNumber: row.RunNumber,
		ConnectionAssignmentRevision: row.Revision, RelayServiceId: row.RelayServiceID}
}

func (h *handler) claimPrivatePublisherConnection(w http.ResponseWriter, r *http.Request, id relayv1.Identifier) {
	var body relayv1.PrivatePublisherConnectionClaim
	if !serviceapi.DecodeJSON(w, r, &body) {
		return
	}
	if !opaqueid.Valid(id, opaqueid.PublisherConnectionPrefix) || !opaqueid.Valid(body.PrivateServiceId, opaqueid.PrivateServicePrefix) ||
		!opaqueid.Valid(body.PrivateRunId, opaqueid.PrivateRunPrefix) || body.RunNumber <= 0 || body.ConnectionAssignmentRevision <= 0 || body.RelayLeaseRevision <= 0 {
		serviceapi.WriteProblem(w, 400, "invalid_request", "Private connection claim is invalid")
		return
	}
	store, ok := h.privateConnections(w)
	if !ok {
		return
	}
	row, err := store.ClaimPrivatePublisherConnection(r.Context(), id, body.PrivateServiceId, body.PrivateRunId,
		body.RunNumber, body.ConnectionAssignmentRevision, body.Credential,
		privateRelayIdentity(body.RelayId, body.RelayRunId, body.RelayLeaseRevision), h.service.now())
	if privateRelayProblem(h, w, r, err) {
		return
	}
	serviceapi.WriteJSON(w, 200, privateRelayResponse(row))
}

func (h *handler) readyPrivatePublisherConnection(w http.ResponseWriter, r *http.Request, id relayv1.Identifier) {
	h.privatePublisherTransition(w, r, id, false)
}

func (h *handler) disconnectPrivatePublisherConnection(w http.ResponseWriter, r *http.Request, id relayv1.Identifier) {
	h.privatePublisherTransition(w, r, id, true)
}

func (h *handler) privatePublisherTransition(w http.ResponseWriter, r *http.Request, id string, disconnect bool) {
	var body relayv1.PrivatePublisherConnectionTransition
	if !serviceapi.DecodeJSON(w, r, &body) {
		return
	}
	if !opaqueid.Valid(id, opaqueid.PublisherConnectionPrefix) || !opaqueid.Valid(body.PrivateRunId, opaqueid.PrivateRunPrefix) ||
		body.RunNumber <= 0 || body.ConnectionAssignmentRevision <= 0 || body.RelayLeaseRevision <= 0 {
		serviceapi.WriteProblem(w, 400, "invalid_request", "Private connection transition is invalid")
		return
	}
	store, ok := h.privateConnections(w)
	if !ok {
		return
	}
	lease := privateRelayIdentity(body.RelayId, body.RelayRunId, body.RelayLeaseRevision)
	var row controlstate.PrivatePublisherConnection
	var err error
	if disconnect {
		row, err = store.DisconnectPrivatePublisherConnection(r.Context(), id, body.PrivateRunId,
			body.RunNumber, body.ConnectionAssignmentRevision, lease, h.service.now())
	} else {
		row, err = store.ReadyPrivatePublisherConnection(r.Context(), id, body.PrivateRunId,
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

func (c *DirectClient) ClaimPrivatePublisherConnection(ctx context.Context, id string, body relayv1.PrivatePublisherConnectionClaim) (relayv1.PrivatePublisherConnection, error) {
	store, ok := c.store.(privateConnectionStore)
	if !ok {
		return relayv1.PrivatePublisherConnection{}, errors.New("private publisher connection state is unavailable")
	}
	row, err := store.ClaimPrivatePublisherConnection(ctx, id, body.PrivateServiceId, body.PrivateRunId, body.RunNumber, body.ConnectionAssignmentRevision, body.Credential,
		privateRelayIdentity(body.RelayId, body.RelayRunId, body.RelayLeaseRevision), c.now())
	return privateRelayResponse(row), err
}

func (c *DirectClient) ReadyPrivatePublisherConnection(ctx context.Context, id string, body relayv1.PrivatePublisherConnectionTransition) (relayv1.PrivatePublisherConnection, error) {
	store, ok := c.store.(privateConnectionStore)
	if !ok {
		return relayv1.PrivatePublisherConnection{}, errors.New("private publisher connection state is unavailable")
	}
	row, err := store.ReadyPrivatePublisherConnection(ctx, id, body.PrivateRunId, body.RunNumber, body.ConnectionAssignmentRevision,
		privateRelayIdentity(body.RelayId, body.RelayRunId, body.RelayLeaseRevision), c.now())
	return privateRelayResponse(row), err
}

func (c *DirectClient) DisconnectPrivatePublisherConnection(ctx context.Context, id string, body relayv1.PrivatePublisherConnectionTransition) error {
	store, ok := c.store.(privateConnectionStore)
	if !ok {
		return errors.New("private publisher connection state is unavailable")
	}
	_, err := store.DisconnectPrivatePublisherConnection(ctx, id, body.PrivateRunId, body.RunNumber, body.ConnectionAssignmentRevision,
		privateRelayIdentity(body.RelayId, body.RelayRunId, body.RelayLeaseRevision), c.now())
	return err
}
