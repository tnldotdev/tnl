package muxsession

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"

	quic "github.com/quic-go/quic-go"
)

// QUICTransport owns one UDP socket shared by borrowed QUIC connections and a
// non-QUIC packet view. its caller closes it after joining connections and drain;
// canceling a borrowed dial or closing a borrowed session never closes it.
type QUICTransport struct {
	transport *quic.Transport
	packet    net.PacketConn
	once      sync.Once
	err       error
}

func ListenQUICTransport(network, address string) (*QUICTransport, error) {
	packet, err := net.ListenPacket(network, address)
	if err != nil {
		return nil, err
	}
	return &QUICTransport{transport: &quic.Transport{Conn: packet}, packet: packet}, nil
}

func (t *QUICTransport) DialQUIC(ctx context.Context, address net.Addr, trust *tls.Config, config *quic.Config) (*quic.Conn, error) {
	return t.transport.Dial(ctx, address, trust, config)
}

func (t *QUICTransport) LocalAddr() net.Addr { return t.packet.LocalAddr() }

// NonQUICPackets borrows the socket without transferring ownership. the caller
// must create exactly one view and close it before closing the transport.
func (t *QUICTransport) NonQUICPackets(ctx context.Context) net.PacketConn {
	return NonQUICPacketConn(ctx, t.transport, t.LocalAddr())
}

func (t *QUICTransport) Close() error {
	t.once.Do(func() { t.err = errors.Join(t.transport.Close(), t.packet.Close()) })
	return t.err
}
