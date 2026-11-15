// package ingress selects HTTP services by exact SNI and other public services by destination.
// public visitor TLS terminates at the publisher.
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

	"github.com/tnldotdev/tnl/internal/ingress/clienthello"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

const defaultOpenTimeout = 10 * time.Second

// keep a failed preferred relay from consuming the visitor concurrency budget
// while another connected relay can still serve the service.
const alternateAttemptTimeout = 250 * time.Millisecond

type Metrics interface {
	ObserveTrafficAdmission(string, string)
	IncCapacityRejection(string)
	IncInspectionFailure(string)
	ObserveVisitor(observability.VisitorOutcome)
	ObserveVisitorOpen(bool, time.Duration)
	SetIngressConnections(string, int)
	AddForwardedBytes(string, int64)
	SetIngressStreams(int)
	ObserveRelayAttempt(string, observability.RelayAttemptOutcome)
}

type Config struct {
	AuditSink                 serviceaudit.Sink
	ServerHostname            string
	HandleControl             func(net.Conn) bool
	RelayHostname             string
	HandleRelay               func(net.Conn) bool
	Control                   PublicServiceControl
	Forwarder                 ServiceForwarder
	CurrentLease              func() ingressv1.IngressLease
	IngressPoolID             string
	RecheckInterval           time.Duration
	HardAuthorizationTTL      time.Duration
	RecheckTimeout            time.Duration
	ServicePortRanges         []tcpport.Range
	RequireProxyHeader        bool
	TrustedProxyPeers         []netip.Prefix
	MaxConnections            int
	MaxClientHelloConnections int
	MaxControlConnections     int
	MaxRelayConnections       int
	MaxServiceConnections     int
	OpenTimeout               time.Duration
	Metrics                   Metrics
	Observer                  OperationObserver
	ObserveRecovery           func(ingressv1.ServiceRunReference, string, uint64, time.Time, []byte)
	OnError                   func(error)
	Traffic                   TrafficConfig
	Pending                   PendingConfig
}

type Server struct {
	listener       net.Listener
	config         Config
	openContext    context.Context
	cancelOpens    context.CancelFunc
	admissions     context.Context
	stopAdmissions context.CancelFunc
	closeOnce      sync.Once
	closeErr       error

	mu             sync.Mutex
	connections    map[net.Conn]bool // true for public visitors, false during inspection.
	backends       map[net.Conn]struct{}
	pending        int
	admitted       [connectionKinds]int
	serving        bool
	closing        bool
	done           chan struct{}
	active         sync.WaitGroup
	nextBackend    atomic.Uint64
	nextServiceRun atomic.Uint64
	traffic        *trafficAdmission
	servicePorts   tcpport.Inventory
	services       *ServiceRouting
}

func New(listener net.Listener, config Config) (*Server, error) {
	if listener == nil || config.Control == nil {
		return nil, errors.New("ingress: listener and service forwarding are required")
	}
	if config.MaxConnections <= 0 {
		return nil, errors.New("ingress: connection limits must be positive")
	}
	if config.RequireProxyHeader && len(config.TrustedProxyPeers) == 0 {
		return nil, errors.New("PROXY metadata requires explicit trusted ingress peers")
	}
	if err := admissionDefaults(&config); err != nil {
		return nil, err
	}
	if err := serviceDefaults(&config); err != nil {
		return nil, err
	}
	var err error
	var servicePorts tcpport.Inventory
	if config.ServicePortRanges != nil {
		servicePorts, err = tcpport.NewInventory(config.ServicePortRanges)
		if err != nil {
			return nil, err
		}
	}
	// retain no caller-owned inventory slices after construction.
	config.ServicePortRanges = nil
	config.Traffic, err = config.Traffic.Resolve()
	if err != nil {
		return nil, err
	}
	config.Pending, err = config.Pending.Resolve()
	if err != nil {
		return nil, err
	}
	if config.ServerHostname == "" != (config.HandleControl == nil) {
		return nil, errors.New("ingress: control hostname and handler must be configured together")
	}
	if config.RelayHostname == "" != (config.HandleRelay == nil) {
		return nil, errors.New("ingress: relay hostname and handler must be configured together")
	}
	if config.RelayHostname != "" && config.RelayHostname == config.ServerHostname {
		return nil, errors.New("ingress: control and relay hostnames must be distinct")
	}
	if config.OpenTimeout <= 0 {
		config.OpenTimeout = defaultOpenTimeout
	}
	openContext, cancelOpens := context.WithCancel(context.Background())
	admissions, stopAdmissions := context.WithCancel(context.Background())
	if metrics, ok := config.Metrics.(*observability.Metrics); ok {
		openContext = observability.WithMetrics(openContext, metrics)
	}
	traffic := newTrafficAdmission(config.Traffic, config.Pending)
	server := &Server{
		listener:       listener,
		config:         config,
		openContext:    openContext,
		cancelOpens:    cancelOpens,
		admissions:     admissions,
		stopAdmissions: stopAdmissions,
		connections:    make(map[net.Conn]bool),
		backends:       make(map[net.Conn]struct{}),
		done:           make(chan struct{}),
		traffic:        traffic,
		servicePorts:   servicePorts,
		services:       NewServiceRouting(),
	}
	return server, nil
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
		connection = onceCloseConn(connection)
		if !s.admit(connection) {
			_ = connection.Close()
			continue
		}
		go func() {
			defer s.active.Done()
			finishInspection := sync.OnceFunc(s.finishInspection)
			err := func() (retErr error) {
				defer func() { retErr = errors.Join(retErr, s.release(connection)) }()
				defer finishInspection()
				return s.handle(connection, finishInspection)
			}()
			if err != nil && s.config.OnError != nil {
				s.config.OnError(err)
			}
		}()
	}
}

func (s *Server) Drain(ctx context.Context) error {
	s.StopAccepting()
	_ = s.listener.Close()
	wait := make(chan struct{})
	go func() {
		s.active.Wait()
		close(wait)
	}()
	select {
	case <-wait:
		return s.Close()
	case <-ctx.Done():
		return errors.Join(context.Cause(ctx), s.Close())
	}
}

func (s *Server) StopAccepting() {
	s.stopAdmissions()
	s.mu.Lock()
	s.closing = true
	s.mu.Unlock()
}

// Close cancels and joins every owned accepted connection and backend.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closing = true
		s.mu.Unlock()
		_ = s.listener.Close()
		s.closeErr = s.closeConnections()
		s.services.Close()
		s.active.Wait()
	})
	return s.closeErr
}

func (s *Server) Done() <-chan struct{} { return s.done }

func (s *Server) Ready() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.serving && !s.closing
}

// Load counts physical public visitors, including pending authorization and the
// final socket close. quota reservations never add another physical connection.
func (s *Server) Load() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var visitors int64
	for _, visitor := range s.connections {
		if visitor {
			visitors++
		}
	}
	return visitors
}

func (s *Server) handle(public net.Conn, finishInspection func()) error {
	if err := public.SetReadDeadline(time.Now().Add(clienthello.ClientHelloReadTimeout)); err != nil {
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
	if s.traffic != nil {
		release, reason := s.traffic.source(source.Addr())
		if reason != "" {
			s.rejectCapacity(reason)
			s.observeTraffic("source", "capacity")
			return nil
		}
		s.observeTraffic("source", "accepted")
		defer release()
	}
	_ = public.SetReadDeadline(time.Time{})
	// native database negotiation is not a TLS ClientHello. select a managed
	// service by its trusted destination before attempting HTTPS inspection.
	if s.servicePorts.Contains(int(destination.Port())) || s.config.RequireProxyHeader && destination.Port() != 443 {
		if !s.servicePorts.Contains(int(destination.Port())) {
			return nil
		}
		finishInspection()
		s.markVisitor(public)
		return s.forwardService(s.openContext, &readerConn{Conn: public, reader: reader}, source, destination, "", nil)
	}
	inspected := &readerConn{Conn: public, reader: reader}
	hello, err := clienthello.InspectClientHello(inspected)
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
	canonicalSNI := hello.ServerName == serverName
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
		if !s.handoff(public, source, destination, hello, relayConnection, handler) {
			return nil
		}
		// the selected relay-hostname handler owns the connection after a successful handoff.
		s.transfer(public)
		return nil
	}
	if !canonicalSNI {
		return ErrServiceAdmission
	}
	s.markVisitor(public)
	return s.forwardService(s.openContext, &readerConn{Conn: public, reader: hello.Remainder}, source, destination, hello.ServerName, hello.Prefix)
}

func (s *Server) forwardService(ctx context.Context, public net.Conn, source, destination netip.AddrPort, hostname string, initial []byte) error {
	if s.config.Control == nil {
		return ErrServiceAdmission
	}
	release, rejected := s.admitClass(serviceConnection)
	if release == nil {
		s.rejectCapacity(rejected)
		return nil
	}
	defer release()
	return s.acceptPublic(ctx, public, source, destination, hostname, initial)
}

func (s *Server) handoff(
	public net.Conn,
	source, destination netip.AddrPort,
	hello clienthello.ClientHello,
	kind connectionKind,
	handler func(net.Conn) bool,
) bool {
	release, rejected := s.admitClass(kind)
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
		if !proxyproto.Trusted(public.RemoteAddr(), s.config.TrustedProxyPeers) {
			return netip.AddrPort{}, netip.AddrPort{}, nil, errors.New("untrusted ingress PROXY peer")
		}
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
	if s.traffic != nil && !s.traffic.process() {
		s.rejectCapacity("process_connection_rate")
		s.observeTraffic("source", "capacity")
		return false
	}
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
	s.connections[connection] = false
	// register before launch so Drain cannot miss an accepted handler.
	s.active.Add(1)
	return true
}

func (s *Server) release(connection net.Conn) error {
	s.mu.Lock()
	_, owned := s.connections[connection]
	s.mu.Unlock()
	if owned {
		err := connection.Close()
		s.mu.Lock()
		delete(s.connections, connection)
		s.mu.Unlock()
		return err
	}
	return nil
}

func (s *Server) markVisitor(connection net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, owned := s.connections[connection]; owned {
		s.connections[connection] = true
	}
}

func (s *Server) transfer(connection net.Conn) {
	s.mu.Lock()
	delete(s.connections, connection)
	s.mu.Unlock()
}

func (s *Server) closeConnections() error {
	s.mu.Lock()
	connections := make([]net.Conn, 0, len(s.connections)+len(s.backends))
	for connection := range s.connections {
		connections = append(connections, connection)
	}
	for connection := range s.backends {
		connections = append(connections, connection)
	}
	s.mu.Unlock()
	// capture owned closes before cancellation can let pending handlers retire
	// their sockets. every captured closer returns its retained physical error.
	s.stopAdmissions()
	s.cancelOpens()
	var err error
	for _, connection := range connections {
		err = errors.Join(err, connection.Close())
	}
	return err
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

func tcpAddress(endpoint netip.AddrPort) net.Addr {
	return &net.TCPAddr{IP: net.IP(endpoint.Addr().AsSlice()), Port: int(endpoint.Port())}
}
