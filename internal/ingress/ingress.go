// Package ingress routes opaque TLS streams by exact SNI.
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

	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/relay"
	"github.com/tnldotdev/tnl/internal/router"
	"github.com/tnldotdev/tnl/internal/sourceauth"
	"github.com/tnldotdev/tnl/internal/sourcelimiter"
	"github.com/tnldotdev/tnl/internal/worker"
)

const defaultOpenTimeout = 10 * time.Second

type Route struct {
	ID                string
	Version           uint64
	AllowedIPPrefixes []netip.Prefix
	Backend           worker.RouteBackend
	SourceKey         [32]byte
}

type LookupFunc func(string) (Route, bool)

type UsageConnection interface {
	PolicyDenied(time.Time)
	CapacityDenied(time.Time)
	PublisherOpening(time.Time)
	PublisherOpened(time.Time)
	PublisherOpenFailed(time.Time)
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
	SetStreams(int)
}

type Config struct {
	Lookup              LookupFunc
	LookupChallenge     LookupFunc
	ServerHostname      string
	HandleControl       func(net.Conn) bool
	RequireProxyHeader  bool
	MaxConnections      int
	MaxRouteConnections int
	OpenTimeout         time.Duration
	Metrics             Metrics
	OpenUsage           func(string, uint64, netip.Addr, time.Time) UsageConnection
	OnError             func(error)
}

type Server struct {
	listener net.Listener
	config   Config
	limiter  *sourcelimiter.Limiter

	mu          sync.Mutex
	connections map[net.Conn]struct{}
	backends    map[net.Conn]struct{}
	byRoute     map[string]int
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
	if config.ServerHostname == "" != (config.HandleControl == nil) {
		return nil, errors.New("ingress: control hostname and handler must be configured together")
	}
	if config.OpenTimeout <= 0 {
		config.OpenTimeout = defaultOpenTimeout
	}
	limiter, err := sourcelimiter.New(sourcelimiter.Config{
		OnEntriesChanged: func(entries int) {
			if config.Metrics != nil {
				config.Metrics.SetSourceLimiterEntries(entries)
			}
		},
	})
	if err != nil {
		return nil, err
	}
	return &Server{
		listener:    listener,
		config:      config,
		limiter:     limiter,
		connections: make(map[net.Conn]struct{}),
		backends:    make(map[net.Conn]struct{}),
		byRoute:     make(map[string]int),
		done:        make(chan struct{}),
	}, nil
}

func (s *Server) Serve() error {
	defer close(s.done)
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
		accounted, ok := s.admit(connection)
		if !ok {
			_ = connection.Close()
			if s.config.Metrics != nil {
				s.config.Metrics.IncCapacityRejection("public_connections")
			}
			continue
		}
		go func() {
			defer s.active.Done()
			defer func() {
				if !accounted.transferred.Load() {
					_ = accounted.Close()
				}
			}()
			if err := s.handle(accounted); err != nil && s.config.OnError != nil {
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
		s.closeConnections()
		return nil
	case <-ctx.Done():
		s.closeConnections()
		return ctx.Err()
	}
}

func (s *Server) Done() <-chan struct{} { return s.done }

func (s *Server) handle(public net.Conn) error {
	if err := public.SetReadDeadline(time.Now().Add(router.ClientHelloReadTimeout)); err != nil {
		return nil
	}
	source, destination, reader, err := s.connectionMetadata(public)
	if err != nil {
		return nil
	}
	if !s.limiter.Allow(source.Addr()) {
		if s.config.Metrics != nil {
			s.config.Metrics.IncSourceLimiterRejection()
		}
		return nil
	}
	_ = public.SetReadDeadline(time.Time{})
	inspected := &readerConn{Conn: public, reader: reader}
	hello, err := router.InspectClientHello(inspected)
	if err != nil {
		return nil
	}
	if hello.ServerName == s.config.ServerHostname {
		connection := &readerConn{
			Conn:   &addressConn{Conn: public, remote: source, local: destination},
			reader: hello.Replay,
		}
		if !s.config.HandleControl(connection) {
			return nil
		}
		// The HTTP server owns control connections after a successful handoff.
		s.transfer(public)
		return nil
	}
	route, ok := s.config.Lookup(hello.ServerName)
	routeID := route.ID
	challenge := hello.ACMETLSALPN && s.config.LookupChallenge != nil
	// Challenge lookup replaces ordinary routing to prevent fallback.
	if challenge {
		route, ok = s.config.LookupChallenge(hello.ServerName)
		routeID = hello.ServerName
	}
	if !ok {
		return nil
	}
	var usage UsageConnection
	if !challenge && s.config.OpenUsage != nil {
		usage = s.config.OpenUsage(route.ID, route.Version, source.Addr(), time.Now().UTC())
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
	var admitted bool
	routeID, admitted = s.admitRoute(routeID)
	if !admitted {
		if s.config.Metrics != nil {
			s.config.Metrics.IncCapacityRejection("route_connections")
		}
		if usage != nil {
			usage.CapacityDenied(time.Now().UTC())
		}
		return nil
	}
	defer s.releaseRoute(routeID)

	if usage != nil {
		usage.PublisherOpening(time.Now().UTC())
	}
	streamOpened := false
	if usage != nil {
		defer func() {
			if !streamOpened {
				usage.PublisherOpenFailed(time.Now().UTC())
			}
		}()
	}
	openCtx, cancel := context.WithTimeout(context.Background(), s.config.OpenTimeout)
	stream, err := route.Backend.Open(openCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("ingress: open route: %w", err)
	}
	if usage != nil {
		usage.PublisherOpened(time.Now().UTC())
	}
	if !s.trackBackend(stream) {
		_ = stream.Close()
		return net.ErrClosed
	}
	defer s.releaseBackend(stream)
	defer stream.Close()
	if err := stream.SetDeadline(time.Now().Add(s.config.OpenTimeout)); err != nil {
		return fmt.Errorf("ingress: set source authentication deadline: %w", err)
	}
	purpose := sourceauth.PurposeApplication
	if challenge {
		purpose = sourceauth.PurposeACME
	}
	if err := sourceauth.Client(stream, route.SourceKey, purpose, proxyproto.Header{
		Source: source, Destination: destination,
	}); err != nil {
		return fmt.Errorf("ingress: authenticate source metadata: %w", err)
	}
	_ = stream.SetDeadline(time.Time{})
	if usage != nil {
		usage.StreamOpened(time.Now().UTC())
		streamOpened = true
	}
	replayed := &readerConn{Conn: public, reader: hello.Replay}
	var observeIngress, observeEgress func(int64)
	if usage != nil {
		observeIngress = func(bytes int64) { usage.AddIngress(bytes, time.Now().UTC()) }
		observeEgress = func(bytes int64) { usage.AddEgress(bytes, time.Now().UTC()) }
	}
	result, err := relay.CopyObserved(replayed, stream, observeIngress, observeEgress)
	if s.config.Metrics != nil {
		s.config.Metrics.AddForwardedBytes("ingress_to_agent", result.LeftToRight)
		s.config.Metrics.AddForwardedBytes("agent_to_ingress", result.RightToLeft)
	}
	return err
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

func (s *Server) admit(connection net.Conn) (*accountedConn, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || len(s.connections) >= s.config.MaxConnections {
		return nil, false
	}
	accounted := &accountedConn{Conn: connection, server: s}
	s.connections[accounted] = struct{}{}
	// Register before launch so Drain cannot miss an accepted handler.
	s.active.Add(1)
	return accounted, true
}

func (s *Server) release(connection net.Conn) {
	s.mu.Lock()
	delete(s.connections, connection)
	s.mu.Unlock()
}

func (s *Server) transfer(connection net.Conn) {
	if accounted, ok := connection.(*accountedConn); ok {
		accounted.transferred.Store(true)
	}
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
		s.config.Metrics.SetStreams(active)
	}
	return true
}

func (s *Server) releaseBackend(connection net.Conn) {
	_ = connection.Close()
	s.mu.Lock()
	delete(s.backends, connection)
	active := len(s.backends)
	s.mu.Unlock()
	if s.config.Metrics != nil {
		s.config.Metrics.SetStreams(active)
	}
}

func (s *Server) admitRoute(routeID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.byRoute[routeID] >= s.config.MaxRouteConnections {
		return routeID, false
	}
	s.byRoute[routeID]++
	return routeID, true
}

func (s *Server) releaseRoute(routeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byRoute[routeID]--
	if s.byRoute[routeID] == 0 {
		delete(s.byRoute, routeID)
	}
}

func (s *Server) closeConnections() {
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

type accountedConn struct {
	net.Conn
	server      *Server
	closeOnce   sync.Once
	closeErr    error
	transferred atomic.Bool
}

func (c *accountedConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Conn.Close()
		c.server.release(c)
	})
	return c.closeErr
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
