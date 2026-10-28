package relay

import (
	"context"
	"errors"
	"net"

	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// PublisherConnection is one locally connected publisher assignment.
type PublisherConnection struct {
	ref     tunnelv1.PublisherConnectionRef
	claimed relayv1.ClaimedPublisherConnection
	*streamLifetime
}

func NewPublisherConnection(
	ref tunnelv1.PublisherConnectionRef,
	claimed relayv1.ClaimedPublisherConnection,
	session *tunnel.Session,
) (*PublisherConnection, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	if session == nil {
		return nil, errors.New("relay: tunnel session is required")
	}
	if claimed.ConnectionSlot < 0 || claimed.ConnectionSlot > 1 || publicClaimRef(claimed) != ref {
		return nil, errors.New("relay: claimed publisher connection does not match its reference")
	}
	c := &PublisherConnection{
		ref: ref, claimed: claimed, streamLifetime: newStreamLifetime(session),
	}
	return c, nil
}

func (c *PublisherConnection) Ref() tunnelv1.PublisherConnectionRef { return c.ref }

func (c *PublisherConnection) OpenVisitor(ctx context.Context, visitorConnectionID string) (net.Conn, error) {
	return c.StartVisitor(ctx, visitorConnectionID, false, tunnelv1.StreamReservation{}, nil, nil)
}

func (c *PublisherConnection) OpenPendingVisitor(ctx context.Context, visitorConnectionID string) (net.Conn, error) {
	return c.StartVisitor(ctx, visitorConnectionID, true, tunnelv1.StreamReservation{}, nil, nil)
}

func (c *PublisherConnection) StartVisitor(ctx context.Context, visitorConnectionID string, denied bool, reservation tunnelv1.StreamReservation, initial []byte, events *tunnel.ReturnEvents) (net.Conn, error) {
	return c.startVisitor(ctx, visitorConnectionID, denied, reservation, initial, events, false)
}

func (c *PublisherConnection) StartConfirmedVisitor(ctx context.Context, visitorConnectionID string, denied bool, reservation tunnelv1.StreamReservation, proxy []byte, events *tunnel.ReturnEvents) (net.Conn, error) {
	return c.startVisitor(ctx, visitorConnectionID, denied, reservation, proxy, events, true)
}

func (c *PublisherConnection) startVisitor(ctx context.Context, visitorConnectionID string, denied bool, reservation tunnelv1.StreamReservation, initial []byte, events *tunnel.ReturnEvents, confirm bool) (net.Conn, error) {
	if err := c.beginOpen(); err != nil {
		return nil, err
	}
	header := tunnelv1.VisitorStreamHeader{
		Reservation:     reservation,
		ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.VisitorStream,
		VisitorConnectionID: visitorConnectionID, PublicURLID: c.ref.PublicURLID,
		PublishRunID: c.ref.PublishRunID, PublishRunNumber: c.ref.PublishRunNumber,
		PublisherConnectionID:        c.ref.PublisherConnectionID,
		ConnectionAssignmentRevision: c.ref.ConnectionAssignmentRevision,
		AccessPending:                denied,
	}
	var stream net.Conn
	var err error
	if confirm {
		stream, err = c.session.StartConfirmedVisitorStream(ctx, header, initial, events)
	} else {
		stream, err = c.session.StartVisitorStream(ctx, header, initial, events)
	}
	return c.finishOpen(stream, err)
}
