// Package ingress routes TLS connections by exact SNI hostname without
// terminating their TLS.
package ingress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/routebackend"
	"github.com/tnldotdev/tnl/internal/router"
	"github.com/tnldotdev/tnl/internal/sourcelimiter"
	"github.com/tnldotdev/tnl/internal/streamcopy"
)

const defaultOpenTimeout = 10 * time.Second

const alternateAttemptTimeout = time.Second

const visitorConnectionIDPrefix = "visitor_connection_"

type Route struct {
	ID                string
	RouteVersion      uint64
	RecoveryEpisodeID uint64
	AllowedIPPrefixes []netip.Prefix
	Backends          []routebackend.Backend
}

type LookupFunc func(string) (Route, bool)

type BackendLookupFunc func(string) ([]routebackend.Backend, bool)

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
	IncSourceLimiterRejection()
	SetSourceLimiterEntries(int)
	IncIPAllowlistDenial()
	AddForwardedBytes(string, int64)
	SetIngressStreams(int)
}

type Config struct {
	Lookup                          LookupFunc
	LookupChallenge                 BackendLookupFunc
	ServerHostname                  string
	HandleControl                   func(net.Conn) bool
	RelayHostname                   string
	HandleRelay                     func(net.Conn) bool
	HandleRelayChallenge            func(net.Conn) bool
	RequireProxyHeader              bool
	SourceConnectionRate            float64
	SourceConnectionBurst           int
	MaxConnections                  int
	MaxRouteConnections             int
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
}

type Server struct {
	listener    net.Listener
	config      Config
	limiter     *sourcelimiter.Limiter
	openContext context.Context
	cancelOpens context.CancelFunc

	mu          sync.Mutex
	connections map[net.Conn]struct{}
	backends    map[net.Conn]struct{}
	byRoute     map[string]int
	byChallenge map[string]int
	pending     int
	admitted    [connectionKinds]int
	serving     bool
	closing     bool
	done        chan struct{}
	active      sync.WaitGroup
}

func New(listener net.Listener, config Config) (*Server, error) {
	if listener == nil || config.Lookup == nil {
		return nil, errors.New("ingress: listener and route lookup are required")
	}
	if config.MaxConnections <= 0 || config.MaxRouteConnections <= 0 {
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
	limiter, err := sourcelimiter.New(sourcelimiter.Config{
		Rate: config.SourceConnectionRate, Burst: config.SourceConnectionBurst,
		OnEntriesChanged: func(entries int) {
			if config.Metrics != nil {
				config.Metrics.SetSourceLimiterEntries(entries)
			}
		},
	})
	if err != nil {
		return nil, err
	}
	openContext, cancelOpens := context.WithCancel(context.Background())
	return &Server{
		listener:    listener,
		config:      config,
		limiter:     limiter,
		openContext: openContext,
		cancelOpens: cancelOpens,
		connections: make(map[net.Conn]struct{}),
		backends:    make(map[net.Conn]struct{}),
		byRoute:     make(map[string]int),
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
			s.rejectCapacity("client_hello_connections")
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
		return nil
	}
	source, destination, reader, err := s.connectionMetadata(public)
	if err != nil {
		return nil
	}
	_ = public.SetReadDeadline(time.Time{})
	inspected := &readerConn{Conn: public, reader: reader}
	hello, err := router.InspectClientHello(inspected)
	if err != nil {
		return nil
	}
	serverName, err := naming.CanonicalizeHostname(hello.ServerName)
	if err != nil {
		return nil
	}
	hello.ServerName = serverName
	finishInspection()
	if hello.ServerName == s.config.ServerHostname {
		if !s.handoff(public, source, destination, hello, controlConnection, s.config.HandleControl) {
			return nil
		}
		// The HTTP server owns control connections after a successful handoff.
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
		// The selected relay-hostname handler owns the connection after a successful handoff.
		s.transfer(public)
		return nil
	}
	var route Route
	var backends []routebackend.Backend
	var ok bool
	challenge := hello.ACMETLSALPN
	// An ALPN claim alone cannot authorize challenge forwarding. Require an
	// exact, currently live challenge from control; never fall back to a route.
	if challenge {
		if s.config.LookupChallenge == nil {
			return nil
		}
		backends, ok = s.config.LookupChallenge(hello.ServerName)
	} else {
		if !s.limiter.Allow(source.Addr()) {
			if s.config.Metrics != nil {
				s.config.Metrics.IncSourceLimiterRejection()
			}
			return nil
		}
		route, ok = s.config.Lookup(hello.ServerName)
		backends = route.Backends
	}
	if !ok || len(backends) == 0 {
		return nil
	}
	var usage UsageConnection
	if !challenge && s.config.OpenUsage != nil {
		usage = s.config.OpenUsage(route.ID, route.RouteVersion, source.Addr(), time.Now().UTC())
		if usage != nil {
			defer func() { usage.Close(time.Now().UTC()) }()
		}
	}
	if !challenge && !ipAllowed(source.Addr(), route.AllowedIPPrefixes) {
		if s.config.Metrics != nil {
			s.config.Metrics.IncIPAllowlistDenial()
		}
		if usage != nil {
			usage.PolicyDenied(time.Now().UTC())
		}
		return nil
	}
	kind, key := visitorConnection, route.ID
	if challenge {
		kind, key = challengeConnection, hello.ServerName
	}
	release, rejected := s.admitClass(kind, key)
	if release == nil {
		s.rejectCapacity(rejected)
		if usage != nil {
			usage.CapacityDenied(time.Now().UTC())
		}
		return nil
	}
	defer release()
	var challengeDeadline time.Time
	if challenge {
		challengeDeadline = time.Now().Add(challengeConnectionTimeout)
		if err := public.SetDeadline(challengeDeadline); err != nil {
			return err
		}
	}

	if usage != nil {
		usage.VisitorStreamOpening(time.Now().UTC())
	}
	streamOpened := false
	if usage != nil {
		defer func() {
			if !streamOpened {
				usage.VisitorStreamOpenFailed(time.Now().UTC())
			}
		}()
	}
	header, err := proxyproto.Encode(proxyproto.Header{Source: source, Destination: destination})
	if err != nil {
		return fmt.Errorf("ingress: encode proxy header: %w", err)
	}
	visitorConnectionID, err := opaqueid.New(visitorConnectionIDPrefix)
	if err != nil {
		return fmt.Errorf("ingress: create visitor connection ID: %w", err)
	}
	openTimeout := s.config.OpenTimeout
	if challenge {
		openTimeout = min(openTimeout, time.Until(challengeDeadline))
	}
	openCtx, cancel := context.WithTimeout(s.openContext, openTimeout)
	defer cancel()
	var (
		stream       net.Conn
		committed    int64
		committedErr error
		lastErr      error
		opened       bool
	)
	for index, backend := range backends {
		if err := openCtx.Err(); err != nil {
			lastErr = errors.Join(lastErr, err)
			break
		}
		if backend == nil {
			lastErr = errors.New("ingress: route backend is nil")
			continue
		}
		attemptCtx, stopAttempt := backendAttemptContext(openCtx, len(backends)-index)
		started := time.Now()
		candidate, openErr := backend.Open(attemptCtx, visitorConnectionID)
		if openErr != nil {
			stopAttempt()
			s.observeAttempt(index, openErr, started)
			lastErr = fmt.Errorf("ingress: open route: %w", openErr)
			continue
		}
		if usage != nil && !opened {
			usage.VisitorStreamOpened(time.Now().UTC())
			opened = true
		}
		if !s.trackBackend(candidate) {
			_ = candidate.Close()
			stopAttempt()
			cancel()
			return net.ErrClosed
		}
		written, writeErr := writeSetup(attemptCtx, candidate, header, hello.Prefix)
		stopAttempt()
		s.observeAttempt(index, writeErr, started)
		if writeErr != nil && written == 0 {
			lastErr = errors.Join(writeErr, s.releaseBackend(candidate))
			continue
		}
		stream = candidate
		committed = written
		committedErr = writeErr
		break
	}
	cancel()
	if stream == nil {
		if lastErr == nil {
			lastErr = errors.New("ingress: route has no usable backend")
		}
		return lastErr
	}
	defer s.releaseBackend(stream)
	if usage != nil {
		usage.StreamOpened(time.Now().UTC())
		usage.AddIngress(committed, time.Now().UTC())
		streamOpened = true
	}
	if s.config.Metrics != nil {
		s.config.Metrics.AddForwardedBytes("visitor_to_publisher", committed)
	}
	if committedErr != nil {
		return fmt.Errorf("ingress: write ClientHello after %d bytes: %w", committed, committedErr)
	}
	if challenge {
		if err := stream.SetDeadline(challengeDeadline); err != nil {
			return err
		}
	}
	replayed := &readerConn{Conn: public, reader: hello.Remainder}
	var observeIngress, observeEgress func(int64)
	if usage != nil {
		observeIngress = func(bytes int64) { usage.AddIngress(bytes, time.Now().UTC()) }
	}
	if usage != nil || route.RecoveryEpisodeID != 0 && s.config.ObserveRecovery != nil {
		var recoveryOnce sync.Once
		observeEgress = func(bytes int64) {
			now := time.Now().UTC()
			if usage != nil {
				usage.AddEgress(bytes, now)
			}
			if route.RecoveryEpisodeID != 0 && s.config.ObserveRecovery != nil {
				recoveryOnce.Do(func() {
					s.config.ObserveRecovery(route.ID, route.RouteVersion, route.RecoveryEpisodeID, now)
				})
			}
		}
	}
	result, err := streamcopy.CopyObserved(replayed, stream, observeIngress, observeEgress)
	if s.config.Metrics != nil {
		s.config.Metrics.AddForwardedBytes("visitor_to_publisher", result.LeftToRight)
		s.config.Metrics.AddForwardedBytes("publisher_to_visitor", result.RightToLeft)
	}
	return err
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
		return false
	}
	s.pending++
	s.connections[connection] = struct{}{}
	// Register before launch so Drain cannot miss an accepted handler.
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
	s.mu.Unlock()
	if s.config.Metrics != nil {
		s.config.Metrics.SetIngressStreams(active)
	}
	return true
}

func (s *Server) releaseBackend(connection net.Conn) error {
	s.mu.Lock()
	delete(s.backends, connection)
	active := len(s.backends)
	s.mu.Unlock()
	if s.config.Metrics != nil {
		s.config.Metrics.SetIngressStreams(active)
	}
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

func backendAttemptContext(ctx context.Context, remaining int) (context.Context, context.CancelFunc) {
	if remaining <= 1 {
		return context.WithCancel(ctx)
	}
	deadline, _ := ctx.Deadline()
	// Reserve a share for each alternate even under a short overall deadline.
	return context.WithTimeout(ctx, min(alternateAttemptTimeout, time.Until(deadline)/time.Duration(remaining)))
}

func (s *Server) observeAttempt(index int, err error, started time.Time) {
	if s.config.Observer == nil {
		return
	}
	s.config.Observer.ObserveOperation("IngressBackendAttempt", err, time.Since(started))
	if index != 0 {
		s.config.Observer.ObserveOperation("IngressFallback", err, time.Since(started))
	}
}

// Only PROXY metadata and a zero-byte ClientHello failure can be retried.
// Stop and join the interrupt before clearing deadlines for the live stream.
func writeSetup(ctx context.Context, connection net.Conn, header, prefix []byte) (written int64, err error) {
	deadline, _ := ctx.Deadline()
	if err = connection.SetDeadline(deadline); err != nil {
		return
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
		err = errors.Join(err, ctx.Err(), connection.SetDeadline(time.Time{}))
	}()
	if err = writeAll(connection, header); err != nil {
		return 0, fmt.Errorf("ingress: write proxy header: %w", err)
	}
	written, err = writeAllCount(connection, prefix)
	if err != nil {
		err = fmt.Errorf("ingress: write ClientHello: %w", err)
	}
	return
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

func writeAll(writer io.Writer, data []byte) error {
	_, err := writeAllCount(writer, data)
	return err
}

func writeAllCount(writer io.Writer, data []byte) (int64, error) {
	return io.Copy(writer, bytes.NewReader(data))
}
