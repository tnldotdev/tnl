package ingress

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// OpenPrivate uses the same exact-process relay pool as HTTP, with a separate
// ID-keyed private stream header. it sends no PROXY or visitor bytes itself.
func (f *Forwarder) OpenPrivate(ctx context.Context, relay ingressv1.PrivateServiceRelay, header tunnelv1.PrivateForwardingHeader) (net.Conn, error) {
	if f == nil || f.connector == nil || header.Validate() != nil || relay.TlsServerName == "" || relay.InternalRelayAddress == "" ||
		relay.ConnectionSlot < 0 || relay.ConnectionSlot > 1 || relay.ConnectionAssignmentRevision < 1 || relay.RelayLeaseRevision < 1 ||
		header.PublisherConnectionID != relay.PublisherConnectionId || header.ConnectionSlot != uint8(relay.ConnectionSlot) ||
		header.ConnectionAssignmentRevision != uint64(relay.ConnectionAssignmentRevision) || header.RelayServiceID != relay.RelayServiceId ||
		header.RelayID != relay.RelayId || header.RelayRunID != relay.RelayRunId || header.RelayLeaseRevision != uint64(relay.RelayLeaseRevision) ||
		!relay.LeaseExpiresAt.After(time.Now()) || !header.ExpiresAt.After(time.Now()) {
		return nil, ErrPrivateAdmission
	}
	target := relayTarget{address: relay.InternalRelayAddress, serverName: relay.TlsServerName, relayServiceID: relay.RelayServiceId,
		relayID: relay.RelayId, relayRunID: relay.RelayRunId, relayLeaseRevision: uint64(relay.RelayLeaseRevision)}
	for attempt := 0; ; attempt++ {
		session, reused, err := f.session(ctx, target)
		if err != nil {
			return nil, err
		}
		started := time.Now()
		stream, err := session.OpenPrivateForwardingStream(ctx, header)
		f.observe("IngressForwardingAck", err, started)
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
