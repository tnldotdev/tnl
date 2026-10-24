package ingress

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// OpenPrivate uses the same exact-process relay pool as HTTP, with a separate
// ID-keyed private stream header. it sends no PROXY or visitor bytes itself.
func (f *Forwarder) OpenPrivate(ctx context.Context, relay ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader, events *tunnel.ReturnEvents) (result net.Conn, retErr error) {
	ctx, finish := observability.Start(ctx, "ingress.private_relay_attempt")
	defer func() { finish(retErr) }()
	if f == nil || f.connector == nil || header.Validate() != nil || relay.TlsServerName == "" || relay.InternalRelayAddress == "" ||
		relay.ConnectionSlot < 0 || relay.ConnectionSlot > 1 || relay.ConnectionAssignmentRevision < 1 || relay.RelayLeaseRevision < 1 ||
		tunnel.ServiceForwardingRef(header) != privateRelayRef(header, relay) ||
		header.RelayID != relay.RelayId || header.RelayRunID != relay.RelayRunId || header.RelayLeaseRevision != uint64(relay.RelayLeaseRevision) ||
		!relay.LeaseExpiresAt.After(time.Now()) || !header.ExpiresAt.After(time.Now()) {
		return nil, ErrServiceAdmission
	}
	target := relayTarget{address: relay.InternalRelayAddress, serverName: relay.TlsServerName, relayServiceID: relay.RelayServiceId,
		relayID: relay.RelayId, relayRunID: relay.RelayRunId, relayLeaseRevision: uint64(relay.RelayLeaseRevision)}
	for attempt := 0; ; attempt++ {
		session, reused, err := f.session(ctx, target)
		if err != nil {
			return nil, err
		}
		started := time.Now()
		stream, err := session.StartServiceForwardingStream(ctx, header, nil, events)
		f.observe("IngressForwardingStart", err, started)
		if err == nil {
			return stream, nil
		}
		var rejected *tunnel.ProtocolError
		if errors.As(err, &rejected) || ctx.Err() != nil || session.Err() == nil && f.currentSession(target.key(), session) {
			return nil, err
		}
		err = errors.Join(err, f.invalidate(target.key(), session))
		if !reused || attempt == 1 {
			return nil, err
		}
	}
}

func privateRelayRef(header tunnelv1.ServiceForwardingHeader, relay ingressv1.ServiceRelay) tunnelv1.ServicePublisherConnectionRef {
	// service and run come from the selected private projection; this relay
	// member supplies only its assignment and relay service identity.
	return tunnelv1.ServicePublisherConnectionRef{ServiceID: header.ServiceID, ServiceRunID: header.ServiceRunID, RunNumber: header.RunNumber,
		PublisherConnectionID: relay.PublisherConnectionId, ConnectionSlot: uint8(relay.ConnectionSlot),
		ConnectionAssignmentRevision: uint64(relay.ConnectionAssignmentRevision), RelayServiceID: relay.RelayServiceId}
}
