package muxsession

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
)

const ALPN = "tnl-tunnel/1"

var ErrClosed = errors.New("muxsession: closed")

// Stream is one full-duplex byte stream in a multiplexed session.
type Stream interface {
	net.Conn
	CloseWrite() error
	Reset(code uint32) error
}

// Session opens and accepts independent full-duplex byte streams.
type Session interface {
	OpenStream(context.Context) (Stream, error)
	AcceptStream(context.Context) (Stream, error)
	Close() error
	Done() <-chan struct{}
	Err() error
}

// AcceptedPeer is the network identity capability of an accepted transport.
// ordinary in-memory sessions need only implement Session.
type AcceptedPeer interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	TLSConnectionState() tls.ConnectionState
}

var (
	_ AcceptedPeer = (*quicSession)(nil)
	_ AcceptedPeer = (*yamuxSession)(nil)
)

// Endpoint identifies where a transport connects without tunnel-specific behavior.
type Endpoint struct {
	Address    string
	ServerName string
}

// Connector establishes a multiplexed session to an endpoint.
type Connector interface {
	Connect(context.Context, Endpoint) (Session, error)
}

// ConnectorFunc adapts a function to Connector.
type ConnectorFunc func(context.Context, Endpoint) (Session, error)

func (f ConnectorFunc) Connect(ctx context.Context, endpoint Endpoint) (Session, error) {
	return f(ctx, endpoint)
}

func normalizeClosed(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, net.ErrClosed) {
		return ErrClosed
	}
	return err
}
