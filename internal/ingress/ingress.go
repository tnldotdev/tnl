// Package ingress routes TLS connections by exact SNI hostname without
// terminating their TLS.
package ingress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/routebackend"
	"github.com/tnldotdev/tnl/internal/router"
)

const defaultOpenTimeout = 10 * time.Second

// keep a failed preferred relay from consuming the visitor concurrency budget
// while another connected relay can still serve the public URL.
const alternateAttemptTimeout = 250 * time.Millisecond

const visitorConnectionIDPrefix = "visitor_connection_"

type PublicURL struct {
	ID                string
	PublishRunNumber  uint64
	RecoveryEpisodeID uint64
	AllowedIPPrefixes []netip.Prefix
	Backends          []routebackend.Backend
}

// LookupFunc returns an empty reason for a current public URL. failure reasons
// are fixed labels, never hostnames, identifiers, or error text.
type LookupFunc func(string) (PublicURL, string)

type UsageConnection interface {
	PolicyDenied(time.Time)
	CapacityDenied(time.Time)
	VisitorStreamOpening(time.Time)
	VisitorStreamOpened(time.Time)
	VisitorStreamOpenFailed(time.Time)
	StreamOpened(time.Time)
	AddIngress(int64, time.Time)
	AddEgress(int64, time.Time)
	Close(time.Time)
}

type Metrics interface {
	IncCapacityRejection(string)
	IncInspectionFailure(string)
	IncChallengeRejection(string)
	ObserveVisitor(string)
	ObserveVisitorOpen(bool, time.Duration)
	SetIngressConnections(string, int)
	AddForwardedBytes(string, int64)
	SetIngressStreams(int)
	ObserveRelayAttempt(string, string)
}

type Config struct {
	Lookup                          LookupFunc
	LookupChallenge                 func(string) ([]routebackend.Backend, string)
	ServerHostname                  string
	HandleControl                   func(net.Conn) bool
	RelayHostname                   string
	HandleRelay                     func(net.Conn) bool
	HandleRelayChallenge            func(net.Conn) bool
	RequireProxyHeader              bool
	MaxConnections                  int
	MaxDeniedConnections            int
	MaxClientHelloConnections       int
	MaxChallengeConnections         int
	MaxHostnameChallengeConnections int
	MaxControlConnections           int
	MaxRelayConnections             int
	OpenTimeout                     time.Duration
	Metrics                         Metrics
	Observer                        OperationObserver
	OpenUsage                       func(string, uint64, netip.Addr, time.Time) UsageConnection
	ObserveRecovery                 func(string, uint64, uint64, time.Time)
	OnError                         func(error)
	OnForwardingFailure             func(string, uint64, string, string, int)
}

type Server struct {
	listener    net.Listener
	config      Config
	openContext context.Context
	cancelOpens context.CancelFunc

	mu          sync.Mutex
	connections map[net.Conn]struct{}
	backends    map[net.Conn]struct{}
	byPublicURL map[string]int
	byDenied    map[string]int
	byChallenge map[string]int
	pending     int
	admitted    [connectionKinds]int
	serving     bool
	closing     bool
	done        chan struct{}
	active      sync.WaitGroup
	nextBackend atomic.Uint64
}

func New(listener net.Listener, config Config) (*Server, error) {
	if listener == nil || config.Lookup == nil {
		return nil, errors.New("ingress: listener and route lookup are required")
	}
	if config.MaxConnections <= 0 {
		return nil, errors.New("ingress: connection limits must be positive")
	}
	if err := admissionDefaults(&config); err != nil {
		return nil, err
	}
	if config.ServerHostname == "" != (config.HandleControl == nil) {
		return nil, errors.New("ingress: control hostname and handler must be configured together")
	}
	if config.RelayHostname == "" != (config.HandleRelay == nil) {
		return nil, errors.New("ingress: relay hostname and handler must be configured together")
	}
	if config.HandleRelayChallenge != nil && config.RelayHostname == "" {
		return nil, errors.New("ingress: relay challenge handling requires a relay hostname")
	}
	if config.RelayHostname != "" && config.RelayHostname == config.ServerHostname {
		return nil, errors.New("ingress: control and relay hostnames must be distinct")
	}
	if config.OpenTimeout <= 0 {
		config.OpenTimeout = defaultOpenTimeout
	}
	openContext, cancelOpens := context.WithCancel(context.Background())
	return &Server{
		listener:    listener,
		config:      config,
		openContext: openContext,
		cancelOpens: cancelOpens,
		connections: make(map[net.Conn]struct{}),
		backends:    make(map[net.Conn]struct{}),
		byPublicURL: make(map[string]int),
		byDenied:    make(map[string]int),
		byChallenge: make(map[string]int),
		done:        make(chan struct{}),
	}, nil
}

func (s *Server) Serve() error {
	s.mu.Lock()
	s.serving = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.serving = false
		s.mu.Unlock()
		close(s.done)
	}()
	for {
		connection, err := s.listener.Accept()
		if err != nil {
			s.mu.Lock()
			closing := s.closing
			s.mu.Unlock()
			if closing || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if !s.admit(connection) {
			_ = connection.Close()
			continue
		}
		go func() {
			defer s.active.Done()
			defer s.release(connection)
			finishInspection := sync.OnceFunc(s.finishInspection)
			defer finishInspection()
			if err := s.handle(connection, finishInspection); err != nil && s.config.OnError != nil {
				s.config.OnError(err)
			}
		}()
	}
}

func (s *Server) Drain(ctx context.Context) error {
	s.mu.Lock()
	s.closing = true
	s.mu.Unlock()
	_ = s.listener.Close()
	wait := make(chan struct{})
	go func() {
		s.active.Wait()
		close(wait)
	}()
	select {
	case <-wait:
		s.cancelOpens()
		return nil
	case <-ctx.Done():
		s.closeConnections()
		return ctx.Err()
	}
}

func (s *Server) Done() <-chan struct{} { return s.done }

func (s *Server) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.serving && !s.closing
}

// Load reports the number of admitted public visitor connections.
func (s *Server) Load() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return int64(s.admitted[visitorConnection])
}

func (s *Server) handle(public net.Conn, finishInspection func()) error {
	if err := public.SetReadDeadline(time.Now().Add(router.ClientHelloReadTimeout)); err != nil {
		if s.config.Metrics != nil {
			s.config.Metrics.IncInspectionFailure("deadline")
		}
		return nil
	}
	source, destination, reader, err := s.connectionMetadata(public)
	if err != nil {
		if s.config.Metrics != nil {
			s.config.Metrics.IncInspectionFailure("metadata")
		}
		return nil
	}
	_ = public.SetReadDeadline(time.Time{})
	inspected := &readerConn{Conn: public, reader: reader}
	hello, err := router.InspectClientHello(inspected)
	if err != nil {
		if s.config.Metrics != nil {
			s.config.Metrics.IncInspectionFailure("client_hello")
		}
		return nil
	}
	serverName, err := naming.CanonicalizeHostname(hello.ServerName)
	if err != nil {
		if s.config.Metrics != nil {
			s.config.Metrics.IncInspectionFailure("hostname")
		}
		return nil
	}
	hello.ServerName = serverName
	finishInspection()
	if hello.ServerName == s.config.ServerHostname {
		if !s.handoff(public, source, destination, hello, controlConnection, s.config.HandleControl) {
			return nil
		}
		// the HTTP server owns control connections after a successful handoff.
		s.transfer(public)
		return nil
	}
	if hello.ServerName == s.config.RelayHostname {
		handler := s.config.HandleRelay
		if hello.ACMETLSALPN && s.config.HandleRelayChallenge != nil {
			handler = s.config.HandleRelayChallenge
		}
		if !s.handoff(public, source, destination, hello, relayConnection, handler) {
			return nil
		}
		// the selected relay-hostname handler owns the connection after a successful handoff.
		s.transfer(public)
		return nil
	}
	return s.forward(public, source, destination, hello)
}

func (s *Server) handoff(
	public net.Conn,
	source, destination netip.AddrPort,
	hello router.ClientHello,
	kind connectionKind,
	handler func(net.Conn) bool,
) bool {
	release, rejected := s.admitClass(kind, "")
	if release == nil {
		s.rejectCapacity(rejected)
		return false
	}
	connection := &admittedConn{readerConn: &readerConn{
		Conn:   &addressConn{Conn: public, remote: source, local: destination},
		reader: hello.Replay(),
	}, release: release}
	if !handler(connection) {
		release()
		return false
	}
	return true
}

func (s *Server) connectionMetadata(public net.Conn) (netip.AddrPort, netip.AddrPort, io.Reader, error) {
	if s.config.RequireProxyHeader {
		header, replay, err := proxyproto.Decode(public)
		if err != nil {
			return netip.AddrPort{}, netip.AddrPort{}, nil, err
		}
		return header.Source, header.Destination, replay, nil
	}
	source, err := addressPort(public.RemoteAddr())
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, nil, err
	}
	destination, err := addressPort(public.LocalAddr())
	if err != nil {
		return netip.AddrPort{}, netip.AddrPort{}, nil, err
	}
	return source, destination, public, nil
}

func (s *Server) admit(connection net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || s.pending >= s.config.MaxClientHelloConnections {
		if s.config.Metrics != nil {
			if s.closing {
				s.config.Metrics.IncCapacityRejection("draining")
			} else {
				s.config.Metrics.IncCapacityRejection("client_hello_connections")
			}
		}
		return false
	}
	s.pending++
	if s.config.Metrics != nil {
		s.config.Metrics.SetIngressConnections("client_hello", s.pending)
	}
	s.connections[connection] = struct{}{}
	// register before launch so Drain cannot miss an accepted handler.
	s.active.Add(1)
	return true
}

func (s *Server) release(connection net.Conn) {
	s.mu.Lock()
	_, owned := s.connections[connection]
	delete(s.connections, connection)
	s.mu.Unlock()
	if owned {
		_ = connection.Close()
	}
}

func (s *Server) transfer(connection net.Conn) {
	s.mu.Lock()
	delete(s.connections, connection)
	s.mu.Unlock()
}

func (s *Server) trackBackend(connection net.Conn) bool {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return false
	}
	s.backends[connection] = struct{}{}
	active := len(s.backends)
	if s.config.Metrics != nil {
		s.config.Metrics.SetIngressStreams(active)
	}
	s.mu.Unlock()
	return true
}

func (s *Server) releaseBackend(connection net.Conn) error {
	s.mu.Lock()
	delete(s.backends, connection)
	active := len(s.backends)
	if s.config.Metrics != nil {
		s.config.Metrics.SetIngressStreams(active)
	}
	s.mu.Unlock()
	started := time.Now()
	err := connection.Close()
	if s.config.Observer != nil {
		s.config.Observer.ObserveOperation("IngressBackendCleanup", err, time.Since(started))
	}
	return err
}

func (s *Server) closeConnections() {
	s.cancelOpens()
	s.mu.Lock()
	connections := make([]net.Conn, 0, len(s.connections)+len(s.backends))
	for connection := range s.connections {
		connections = append(connections, connection)
	}
	for connection := range s.backends {
		connections = append(connections, connection)
	}
	s.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}

type readerConn struct {
	net.Conn
	reader io.Reader
}

type addressConn struct {
	net.Conn
	remote netip.AddrPort
	local  netip.AddrPort
}

func (c *addressConn) RemoteAddr() net.Addr { return tcpAddress(c.remote) }

func (c *addressConn) LocalAddr() net.Addr { return tcpAddress(c.local) }

func (c *readerConn) Read(destination []byte) (int, error) {
	return c.reader.Read(destination)
}

func (c *readerConn) CloseRead() error {
	if closer, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return closer.CloseRead()
	}
	return errors.ErrUnsupported
}

func (c *readerConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return errors.ErrUnsupported
}

func addressPort(address net.Addr) (netip.AddrPort, error) {
	endpoint, err := netip.ParseAddrPort(address.String())
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("ingress: parse connection address: %w", err)
	}
	return endpoint, nil
}

func ipAllowed(source netip.Addr, prefixes []netip.Prefix) bool {
	if len(prefixes) == 0 {
		return true
	}
	source = source.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(source) {
			return true
		}
	}
	return false
}

func tcpAddress(endpoint netip.AddrPort) net.Addr {
	return &net.TCPAddr{IP: net.IP(endpoint.Addr().AsSlice()), Port: int(endpoint.Port())}
}
