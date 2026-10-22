package muxsession

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

const defaultQUICKeepAlivePeriod = 30 * time.Second

const compatibleQUICPacketSize = 1200

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
	return connectQUIC(ctx, endpoint, c.TLSConfig, c.Config, ALPN)
}

type ConnectorQUIC struct {
	TLSConfig *tls.Config
	Config    QUICConfig
}

func (c ConnectorQUIC) Connect(ctx context.Context, endpoint Endpoint) (Session, error) {
	return connectQUIC(ctx, endpoint, c.TLSConfig, c.Config, ConnectorALPN)
}

func connectQUIC(ctx context.Context, endpoint Endpoint, roots *tls.Config, transport QUICConfig, alpn string) (Session, error) {
	if endpoint.Address == "" || endpoint.ServerName == "" {
		return nil, errors.New("muxsession: QUIC endpoint requires address and server name")
	}
	tlsConfig, err := transportTLSConfigForALPN(roots, endpoint.ServerName, false, alpn)
	if err != nil {
		return nil, err
	}
	config := quicConnectorConfig(transport.Config)
	if config.KeepAlivePeriod == 0 {
		config.KeepAlivePeriod = defaultQUICKeepAlivePeriod
	}
	connection, err := quic.DialAddr(ctx, endpoint.Address, tlsConfig, config)
	if err != nil {
		return nil, fmt.Errorf("muxsession: dial QUIC: %w", err)
	}
	if err := requireTransportALPN(connection.ConnectionState().TLS, alpn); err != nil {
		_ = connection.CloseWithError(1, "unexpected publisher transport protocol")
		return nil, err
	}
	return &quicSession{connection: connection}, nil
}

// QUICListener accepts QUIC multiplexed sessions.
type QUICListener struct {
	listener   *quic.Listener
	transport  *quic.Transport
	packetConn net.PacketConn
	closeOnce  sync.Once
	closeErr   error
	alpn       string
	protocols  map[string]struct{}
}

// ListenQUIC starts a QUIC listener. the returned listener never accepts 0-RTT.
func ListenQUIC(address string, tlsConfig *tls.Config, config QUICConfig) (*QUICListener, error) {
	return listenQUICWithALPN(address, tlsConfig, config, ALPN)
}

func ListenConnectorQUIC(address string, tlsConfig *tls.Config, config QUICConfig) (*QUICListener, error) {
	return listenQUICWithALPN(address, tlsConfig, config, ConnectorALPN)
}

// ListenQUICProtocols shares one infrastructure socket across the two tunnel
// ALPNs. the owner selects the role by the verified handshake's SNI and ALPN.
func ListenQUICProtocols(address string, tlsConfig *tls.Config, config QUICConfig) (*QUICListener, error) {
	if tlsConfig == nil {
		return nil, errors.New("muxsession: TLS configuration is required")
	}
	serverConfig := tlsConfig.Clone()
	serverConfig.MinVersion = tls.VersionTLS13
	serverConfig.NextProtos = []string{ALPN, ConnectorALPN}
	listener, transport, packetConn, err := listenQUIC(address, serverConfig, quicConfig(config.Config))
	if err != nil {
		return nil, fmt.Errorf("muxsession: listen shared QUIC: %w", err)
	}
	return &QUICListener{listener: listener, transport: transport, packetConn: packetConn, protocols: map[string]struct{}{ALPN: {}, ConnectorALPN: {}}}, nil
}

func listenQUICWithALPN(address string, tlsConfig *tls.Config, config QUICConfig, alpn string) (*QUICListener, error) {
	serverConfig, err := transportTLSConfigForALPN(tlsConfig, "", true, alpn)
	if err != nil {
		return nil, err
	}
	listener, transport, packetConn, err := listenQUIC(address, serverConfig, quicConfig(config.Config))
	if err != nil {
		return nil, fmt.Errorf("muxsession: listen QUIC: %w", err)
	}
	return &QUICListener{listener: listener, transport: transport, packetConn: packetConn, alpn: alpn}, nil
}

func listenQUIC(address string, tlsConfig *tls.Config, config *quic.Config) (*quic.Listener, *quic.Transport, net.PacketConn, error) {
	if !requiresBasicQUICPacketConn(address) {
		return listenQUICPacket("udp", address, tlsConfig, config, false)
	}
	// Fly UDP replies must follow the socket route; quic-go's IP_PKTINFO
	// interface pinning and larger datagrams fail on its forwarding path.
	return listenBasicQUIC(address, tlsConfig, flyQUICConfig(config))
}

func flyQUICConfig(config *quic.Config) *quic.Config {
	config = config.Clone()
	config.InitialPacketSize = compatibleQUICPacketSize
	config.DisablePathMTUDiscovery = true
	return config
}

func quicConnectorConfig(config *quic.Config) *quic.Config {
	config = quicConfig(config)
	if config.InitialPacketSize == 0 {
		config.InitialPacketSize = compatibleQUICPacketSize
	}
	return config
}

func listenBasicQUIC(address string, tlsConfig *tls.Config, config *quic.Config) (*quic.Listener, *quic.Transport, net.PacketConn, error) {
	return listenQUICPacket("udp4", address, tlsConfig, config, true)
}

func listenQUICPacket(network, address string, tlsConfig *tls.Config, config *quic.Config, basic bool) (*quic.Listener, *quic.Transport, net.PacketConn, error) {
	udpAddress, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, nil, nil, err
	}
	packetConn, err := net.ListenUDP(network, udpAddress)
	if err != nil {
		return nil, nil, nil, err
	}
	var connection net.PacketConn = packetConn
	if basic {
		connection = struct{ net.PacketConn }{packetConn}
	}
	transport := &quic.Transport{Conn: connection}
	listener, err := transport.Listen(tlsConfig, config)
	if err != nil {
		_ = transport.Close()
		_ = packetConn.Close()
		return nil, nil, nil, err
	}
	return listener, transport, packetConn, nil
}

func requiresBasicQUICPacketConn(address string) bool {
	host, _, err := net.SplitHostPort(address)
	return err == nil && host == "fly-global-services"
}

func (l *QUICListener) Accept(ctx context.Context) (Session, error) {
	connection, err := l.listener.Accept(ctx)
	if err != nil {
		return nil, normalizeQUICError(err)
	}
	if l.protocols != nil {
		if _, ok := l.protocols[connection.ConnectionState().TLS.NegotiatedProtocol]; !ok {
			_ = connection.CloseWithError(1, "unexpected transport protocol")
			return nil, errors.New("muxsession: unexpected shared QUIC ALPN")
		}
		return &quicSession{connection: connection}, nil
	}
	alpn := l.alpn
	if alpn == "" {
		alpn = ALPN
	}
	if err := requireTransportALPN(connection.ConnectionState().TLS, alpn); err != nil {
		_ = connection.CloseWithError(1, "unexpected publisher transport protocol")
		return nil, err
	}
	return &quicSession{connection: connection}, nil
}

func (l *QUICListener) Addr() net.Addr { return l.listener.Addr() }

// StopAccepting leaves accepted connections alive while the relay drains them.
func (l *QUICListener) StopAccepting() error {
	return normalizeQUICError(l.listener.Close())
}

// Close completes ownership of the transport and socket after draining. closing
// only quic.Listener leaves accepted connections and connection-ID retirement
// timers alive, so the same UDP address may not be immediately reusable.
func (l *QUICListener) Close() error {
	l.closeOnce.Do(func() {
		l.closeErr = errors.Join(l.StopAccepting(), normalizeQUICError(l.transport.Close()), l.packetConn.Close())
	})
	return l.closeErr
}

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

func (s *quicSession) LocalAddr() net.Addr  { return s.connection.LocalAddr() }
func (s *quicSession) RemoteAddr() net.Addr { return s.connection.RemoteAddr() }
func (s *quicSession) TLSConnectionState() tls.ConnectionState {
	return s.connection.ConnectionState().TLS
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
