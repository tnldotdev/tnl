package relay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var errConnectorSocketSourceChanged = &tunnel.ProtocolError{Code: tunnelv1.StaleNetworkBinding}
var errConnectorSocketSource = errors.New("relay: invalid connector socket source")

// validation failure after an accepted source was pinned is evidence of a
// changed binding, not an independent authorization denial.
type connectorSocketSourceChange struct{ validation error }

func (e *connectorSocketSourceChange) Error() string {
	return "relay: accepted connector socket source changed: " + e.validation.Error()
}

func (e *connectorSocketSourceChange) Unwrap() []error {
	return []error{errConnectorSocketSourceChanged, e.validation}
}

// connectorSocketSource binds one physical carrier to its accepted source IP.
// QUIC may change RemoteAddr without closing; a detected change is irreversible
// for this carrier, even if the socket later returns to its original address.
type connectorSocketSource struct {
	peer  muxsession.AcceptedPeer
	ip    netip.Addr
	stale atomic.Bool
}

func newConnectorSocketSource(accepted muxsession.AcceptedPeer) (*connectorSocketSource, error) {
	ip, err := connectorSocketIP(accepted)
	if err != nil {
		return nil, err
	}
	if _, udp := accepted.RemoteAddr().(*net.UDPAddr); udp {
		bound, ok := accepted.(muxsession.IPBoundPeer)
		if !ok || !bound.RemoteIPBound() {
			return nil, errConnectorSocketSource
		}
	}
	return &connectorSocketSource{peer: accepted, ip: ip}, nil
}

func connectorSocketIP(accepted muxsession.AcceptedPeer) (netip.Addr, error) {
	if accepted == nil {
		return netip.Addr{}, errConnectorSocketSource
	}
	address := accepted.RemoteAddr()
	switch socket := address.(type) {
	case *net.TCPAddr:
		if socket == nil {
			return netip.Addr{}, errConnectorSocketSource
		}
	case *net.UDPAddr:
		if socket == nil {
			return netip.Addr{}, errConnectorSocketSource
		}
	default:
		return netip.Addr{}, errConnectorSocketSource
	}
	socket, err := netip.ParseAddrPort(address.String())
	if err != nil || socket.Addr().Unmap().IsUnspecified() || socket.Addr().Zone() != "" {
		return netip.Addr{}, errConnectorSocketSource
	}
	return socket.Addr().Unmap(), nil
}

func (s *connectorSocketSource) check() error {
	if s == nil {
		return nil
	}
	if s.stale.Load() {
		return errConnectorSocketSourceChanged
	}
	ip, err := connectorSocketIP(s.peer)
	if err != nil || ip != s.ip {
		s.stale.Store(true)
		if err != nil {
			return &connectorSocketSourceChange{validation: err}
		}
		return errConnectorSocketSourceChanged
	}
	if s.stale.Load() {
		return errConnectorSocketSourceChanged
	}
	return nil
}

// connectorSourceCarrier checks source authority at each packet operation, not
// just at renewal. an entered framed write finishes with its original context;
// a post-write check retires that carrier rather than reusing a partial stream.
// input is checked again after a blocking read, before it can reach forwarding.
// these checks are defense in depth: an outer QUIC transport must reject an IP
// change before dispatching frames. RemoteAddr checks alone cannot enforce that.
type connectorSourceCarrier struct {
	peer.Carrier
	source *connectorSocketSource
}

// connectorBindingCarrier owns physical readiness and source checks. its bridge
// supplies packet admission; the carrier keeps no copy of binding authority.
// it never validates an endpoint MAC or holds SessionKey.
type connectorBindingCarrier struct {
	peer.Carrier
	source      *connectorSocketSource
	admitPacket func(tunnelv1.PeerPacket) bool
	ready       atomic.Bool
	cancel      context.CancelFunc
}

func newConnectorBindingCarrier(carrier peer.Carrier, source *connectorSocketSource, admit func(tunnelv1.PeerPacket) bool, cancel context.CancelFunc) *connectorBindingCarrier {
	return &connectorBindingCarrier{Carrier: &connectorSourceCarrier{Carrier: carrier, source: source}, source: source, admitPacket: admit, cancel: cancel}
}

func (c *connectorBindingCarrier) permits(frame []byte) bool {
	packet, err := tunnelv1.ParsePeerPacket(frame)
	return err == nil && c.admitPacket(packet)
}

func (c *connectorBindingCarrier) Send(ctx context.Context, frame []byte) error {
	if err := c.source.check(); err != nil {
		return err
	}
	// a TLS stream introduces itself with its first authenticated packet.
	// publisher probes before then are dropped, never queued or replayed.
	if !c.ready.Load() || !c.permits(frame) {
		return context.Cause(ctx)
	}
	err := c.Carrier.Send(ctx, frame)
	if err != nil && !errors.Is(err, errConnectorSocketSourceChanged) {
		c.cancel()
	}
	return err
}

func (c *connectorBindingCarrier) Receive(ctx context.Context) ([]byte, error) {
	for {
		frame, err := c.Carrier.Receive(ctx)
		if err != nil {
			if !errors.Is(err, errConnectorSocketSourceChanged) {
				c.cancel()
			}
			return nil, err
		}
		if c.permits(frame) {
			c.ready.Store(true)
			return frame, nil
		}
	}
}

func (c *connectorBindingCarrier) Close() error {
	// source migration retires packets but leaves the bounded control stream
	// alive to report the exact stale result, rather than an outer close.
	if !errors.Is(c.source.check(), errConnectorSocketSourceChanged) {
		c.cancel()
	}
	return c.Carrier.Close()
}

func (c *connectorSourceCarrier) Send(ctx context.Context, frame []byte) error {
	if err := c.source.check(); err != nil {
		return err
	}
	err := c.Carrier.Send(ctx, frame)
	return errors.Join(err, c.source.check())
}

func (c *connectorSourceCarrier) Receive(ctx context.Context) ([]byte, error) {
	if err := c.source.check(); err != nil {
		return nil, err
	}
	frame, err := c.Carrier.Receive(ctx)
	if err = errors.Join(err, c.source.check()); err != nil {
		return nil, err
	}
	return frame, nil
}
