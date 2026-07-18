package muxsession

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	quic "github.com/quic-go/quic-go"
)

const defaultQUICKeepAlivePeriod = 30 * time.Second

// QUICConfig configures the QUIC transport.
type QUICConfig struct {
	Config *quic.Config
}

// QUICConnector establishes QUIC multiplexed sessions.
type QUICConnector struct {
	TLSConfig *tls.Config
	Config    QUICConfig
}

func (c QUICConnector) Connect(ctx context.Context, endpoint Endpoint) (Session, error) {
	if endpoint.Address == "" || endpoint.ServerName == "" {
		return nil, errors.New("muxsession: QUIC endpoint requires address and server name")
	}
	tlsConfig, err := transportTLSConfig(c.TLSConfig, endpoint.ServerName, false)
	if err != nil {
		return nil, err
	}
	config := quicConfig(c.Config.Config)
	if config.KeepAlivePeriod == 0 {
		config.KeepAlivePeriod = defaultQUICKeepAlivePeriod
	}
	connection, err := quic.DialAddr(ctx, endpoint.Address, tlsConfig, config)
	if err != nil {
		return nil, fmt.Errorf("muxsession: dial QUIC: %w", err)
	}
	if err := requireALPN(connection.ConnectionState().TLS); err != nil {
		_ = connection.CloseWithError(1, err.Error())
		return nil, err
	}
	return &quicSession{connection: connection}, nil
}

// QUICListener accepts QUIC multiplexed sessions.
type QUICListener struct {
	listener *quic.Listener
}

// ListenQUIC starts a QUIC listener. The returned listener never accepts 0-RTT.
func ListenQUIC(address string, tlsConfig *tls.Config, config QUICConfig) (*QUICListener, error) {
	serverConfig, err := transportTLSConfig(tlsConfig, "", true)
	if err != nil {
		return nil, err
	}
	listener, err := quic.ListenAddr(address, serverConfig, quicConfig(config.Config))
	if err != nil {
		return nil, fmt.Errorf("muxsession: listen QUIC: %w", err)
	}
	return &QUICListener{listener: listener}, nil
}

func (l *QUICListener) Accept(ctx context.Context) (Session, error) {
	connection, err := l.listener.Accept(ctx)
	if err != nil {
		return nil, normalizeQUICError(err)
	}
	if err := requireALPN(connection.ConnectionState().TLS); err != nil {
		_ = connection.CloseWithError(1, err.Error())
		return nil, err
	}
	return &quicSession{connection: connection}, nil
}

func (l *QUICListener) Addr() net.Addr { return l.listener.Addr() }

func (l *QUICListener) Close() error { return normalizeQUICError(l.listener.Close()) }

func quicConfig(config *quic.Config) *quic.Config {
	if config == nil {
		config = new(quic.Config)
	} else {
		config = config.Clone()
	}
	config.Allow0RTT = false
	config.EnableDatagrams = false
	if config.MaxIncomingStreams == 0 {
		config.MaxIncomingStreams = defaultMaxIncomingStreams
	}
	if config.MaxIncomingUniStreams == 0 {
		config.MaxIncomingUniStreams = -1
	}
	return config
}

type quicSession struct {
	connection *quic.Conn
}

func (s *quicSession) OpenStream(ctx context.Context) (Stream, error) {
	stream, err := s.connection.OpenStreamSync(ctx)
	if err != nil {
		return nil, normalizeQUICError(err)
	}
	return &quicStream{
		Stream: stream,
		local:  s.connection.LocalAddr(),
		remote: s.connection.RemoteAddr(),
	}, nil
}

func (s *quicSession) AcceptStream(ctx context.Context) (Stream, error) {
	stream, err := s.connection.AcceptStream(ctx)
	if err != nil {
		return nil, normalizeQUICError(err)
	}
	return &quicStream{
		Stream: stream,
		local:  s.connection.LocalAddr(),
		remote: s.connection.RemoteAddr(),
	}, nil
}

func (s *quicSession) Close() error {
	return normalizeQUICError(s.connection.CloseWithError(0, ""))
}

func (s *quicSession) Done() <-chan struct{} { return s.connection.Context().Done() }

func (s *quicSession) Err() error {
	select {
	case <-s.Done():
		return normalizeQUICError(context.Cause(s.connection.Context()))
	default:
		return nil
	}
}

func normalizeQUICError(err error) error {
	if err == nil {
		return nil
	}
	var applicationError *quic.ApplicationError
	if errors.As(err, &applicationError) && applicationError.ErrorCode == 0 {
		return ErrClosed
	}
	return normalizeClosed(err)
}

type quicStream struct {
	*quic.Stream
	local  net.Addr
	remote net.Addr
}

func (s *quicStream) Close() error {
	s.Stream.CancelRead(0)
	return s.Stream.Close()
}

func (s *quicStream) CloseWrite() error { return s.Stream.Close() }

func (s *quicStream) Reset(code uint32) error {
	errorCode := quic.StreamErrorCode(code)
	s.Stream.CancelRead(errorCode)
	s.Stream.CancelWrite(errorCode)
	return nil
}

func (s *quicStream) LocalAddr() net.Addr { return s.local }

func (s *quicStream) RemoteAddr() net.Addr { return s.remote }
