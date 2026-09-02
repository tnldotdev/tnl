package tailtransport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/tailscale/tailcat"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
)

const sessionTCPPort uint16 = 443

var (
	errAlreadyStarted = errors.New("tailtransport: already started")
	errNotReady       = errors.New("tailtransport: not ready")
)

type sessionStatus uint8

const (
	statusNew sessionStatus = iota
	statusStarting
	statusReady
	statusDraining
	statusFailed
	statusClosed
)

type lifecycle struct {
	mu     sync.Mutex
	status sessionStatus
}

type operationGate struct {
	mu       sync.Mutex
	shutdown context.Context
	cancel   context.CancelCauseFunc
	closed   bool
	active   sync.WaitGroup
}

func newOperationGate() *operationGate {
	shutdown, cancel := context.WithCancelCause(context.Background())
	return &operationGate{shutdown: shutdown, cancel: cancel}
}

func (g *operationGate) begin(ctx context.Context) (context.Context, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil, nil, net.ErrClosed
	}
	operationCtx, cancel := context.WithCancelCause(ctx)
	stopShutdown := context.AfterFunc(g.shutdown, func() { cancel(net.ErrClosed) })
	g.active.Add(1)
	g.mu.Unlock()

	done := sync.OnceFunc(func() {
		stopShutdown()
		cancel(context.Canceled)
		g.active.Done()
	})
	return operationCtx, done, nil
}

func (g *operationGate) closeAndWait() {
	g.mu.Lock()
	if !g.closed {
		g.closed = true
		g.cancel(net.ErrClosed)
	}
	g.mu.Unlock()
	g.active.Wait()
}

func operationError(ctx context.Context, err error) error {
	if errors.Is(context.Cause(ctx), net.ErrClosed) {
		return net.ErrClosed
	}
	return err
}

func (l *lifecycle) beginStart() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.status == statusClosed {
		return net.ErrClosed
	}
	if l.status != statusNew {
		return errAlreadyStarted
	}
	l.status = statusStarting
	return nil
}

func (l *lifecycle) finishStart() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.status != statusStarting {
		return l.statusErrorLocked()
	}
	l.status = statusReady
	return nil
}

func (l *lifecycle) failStart() {
	l.mu.Lock()
	if l.status == statusStarting {
		l.status = statusFailed
	}
	l.mu.Unlock()
}

func (l *lifecycle) ready() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.status == statusReady {
		return nil
	}
	return l.statusErrorLocked()
}

func (l *lifecycle) beginDrain() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch l.status {
	case statusReady:
		l.status = statusDraining
		return nil
	case statusDraining:
		return nil
	default:
		return l.statusErrorLocked()
	}
}

func (l *lifecycle) close() {
	l.mu.Lock()
	l.status = statusClosed
	l.mu.Unlock()
}

func (l *lifecycle) statusErrorLocked() error {
	switch l.status {
	case statusClosed:
		return net.ErrClosed
	case statusDraining:
		return errDraining
	default:
		return errNotReady
	}
}

// ServerConfig configures the publisher side of one session transport.
type ServerConfig struct {
	AllowedClient key.NodePublic
	RelayRegion   string
	Regions       map[string]*tailcfg.DERPRegion
	Handler       func(net.Conn)
	Logf          logger.Logf
}

// Server accepts streams from one pre-authorized hosted dialer.
type Server struct {
	allowedClient key.NodePublic
	relayRegion   string
	region        *tailcfg.DERPRegion
	handler       func(net.Conn)
	logf          logger.Logf
	lifecycle     lifecycle
	streams       *streamRegistry
	operations    *operationGate
	server        tailcatServer
	newServer     func(*tailcat.Server) tailcatServer
	closeOnce     sync.Once
	closeErr      error
}

type tailcatServer interface {
	Start() error
	DrainTCP(context.Context) error
	Close() error
}

// NewServer validates and snapshots config without starting network activity.
func NewServer(config ServerConfig) (*Server, error) {
	if config.AllowedClient.IsZero() {
		return nil, errors.New("tailtransport: missing allowed client key")
	}
	region, err := relayRegion(config.RelayRegion, config.Regions)
	if err != nil {
		return nil, err
	}
	if config.Handler == nil {
		return nil, errors.New("tailtransport: missing stream handler")
	}
	return &Server{
		allowedClient: config.AllowedClient,
		relayRegion:   config.RelayRegion,
		region:        region,
		handler:       config.Handler,
		logf:          config.Logf,
		streams:       newStreamRegistry(),
		operations:    newOperationGate(),
		newServer:     func(server *tailcat.Server) tailcatServer { return server },
	}, nil
}

// Start starts the server and returns the endpoint advertised to hosted
// ingress. It may be called only once.
func (s *Server) Start(ctx context.Context) (TransportDescriptor, error) {
	var zero TransportDescriptor
	if err := s.lifecycle.beginStart(); err != nil {
		return zero, err
	}
	operationCtx, done, err := s.operations.begin(ctx)
	if err != nil {
		s.lifecycle.failStart()
		return zero, err
	}
	defer done()

	serverKey := key.NewNode()
	tc := s.newServer(&tailcat.Server{
		Key:            serverKey,
		Logf:           s.logf,
		Region:         s.region,
		AllowedClients: []key.NodePublic{s.allowedClient},
		ServedTCPPorts: []filter.PortRange{{First: sessionTCPPort, Last: sessionTCPPort}},
		OnTCP: func(port uint16) func(net.Conn) {
			if port != sessionTCPPort {
				return nil
			}
			return s.handle
		},
	})

	s.server = tc
	err = tc.Start()
	if err == nil {
		err = operationCtx.Err()
	}
	if err == nil {
		err = s.lifecycle.finishStart()
	}
	if err != nil {
		s.lifecycle.failStart()
		s.server = nil
		tc.Close()
	}
	if err != nil {
		return zero, operationError(operationCtx, err)
	}
	return TransportDescriptor{Version: descriptorVersion, PublisherPublicKey: serverKey.Public().String(), RelayRegion: s.relayRegion}, nil
}

func (s *Server) handle(conn net.Conn) {
	if err := s.lifecycle.ready(); err != nil {
		conn.Close()
		return
	}
	tracked, err := s.streams.track(conn)
	if err != nil {
		return
	}
	defer tracked.Close()
	s.handler(tracked)
}

// Drain rejects new streams and waits for existing TCP streams to fully close.
// Callers should provide a deadline.
func (s *Server) Drain(ctx context.Context) error {
	if err := s.lifecycle.beginDrain(); err != nil {
		return err
	}
	operationCtx, done, err := s.operations.begin(ctx)
	if err != nil {
		return err
	}
	defer done()
	if err := s.streams.drain(operationCtx); err != nil {
		return fmt.Errorf("drain streams: %w", operationError(operationCtx, err))
	}
	err = s.server.DrainTCP(operationCtx)
	if err == nil {
		err = operationCtx.Err()
	}
	if err != nil {
		return fmt.Errorf("drain tailcat TCP: %w", operationError(operationCtx, err))
	}
	return nil
}

// Close terminally stops the server, cancels context-aware calls, and waits for
// admitted operations.
func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.lifecycle.close()
		s.streams.close()
		s.operations.closeAndWait()
		if s.server != nil {
			s.closeErr = s.server.Close()
		}
	})
	return s.closeErr
}

// DialerConfig configures the hosted-ingress side of one session transport.
type DialerConfig struct {
	Endpoint TransportDescriptor
	Regions  map[string]*tailcfg.DERPRegion
	Key      key.NodePrivate
	Logf     logger.Logf
}

// Dialer owns one reusable hosted-ingress Tailcat client for a session.
type Dialer struct {
	key        key.NodePrivate
	logf       logger.Logf
	blob       tailcat.ConnBlob
	lifecycle  lifecycle
	streams    *streamRegistry
	operations *operationGate
	client     tailcatClient
	newClient  func(*tailcat.Client) tailcatClient
	closeOnce  sync.Once
	closeErr   error
}

type tailcatClient interface {
	Ping(context.Context) (tailcat.PingResult, error)
	DialTCPPort(context.Context, uint16) (net.Conn, error)
	Close() error
}

// NewDialer validates the endpoint against local relay regions without
// starting network activity.
func NewDialer(config DialerConfig) (*Dialer, error) {
	if config.Key.IsZero() {
		return nil, errors.New("tailtransport: missing client key")
	}
	blob, err := connBlob(config.Endpoint, config.Regions)
	if err != nil {
		return nil, err
	}
	return &Dialer{
		key:        config.Key,
		logf:       config.Logf,
		blob:       blob,
		streams:    newStreamRegistry(),
		operations: newOperationGate(),
		newClient:  func(client *tailcat.Client) tailcatClient { return client },
	}, nil
}

// Start establishes connectivity to the session server. It may be called only
// once.
func (d *Dialer) Start(ctx context.Context) error {
	if err := d.lifecycle.beginStart(); err != nil {
		return err
	}
	operationCtx, done, err := d.operations.begin(ctx)
	if err != nil {
		d.lifecycle.failStart()
		return err
	}
	defer done()

	tc := d.newClient(&tailcat.Client{Server: d.blob, Key: d.key, Logf: d.logf})
	d.client = tc
	_, err = tc.Ping(operationCtx)
	for errors.Is(err, context.DeadlineExceeded) && operationCtx.Err() == nil {
		_, err = tc.Ping(operationCtx)
	}
	if err == nil {
		err = d.lifecycle.finishStart()
	}
	if err != nil {
		d.lifecycle.failStart()
		d.client = nil
		tc.Close()
	}
	return operationError(operationCtx, err)
}

// Open creates a TCP stream to the session server.
func (d *Dialer) Open(ctx context.Context) (net.Conn, error) {
	if err := d.lifecycle.ready(); err != nil {
		return nil, err
	}
	operationCtx, done, err := d.operations.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	if err := d.streams.beginOpen(); err != nil {
		return nil, err
	}
	if err := d.lifecycle.ready(); err != nil {
		return d.streams.finishOpen(nil, err)
	}
	conn, err := d.client.DialTCPPort(operationCtx, sessionTCPPort)
	if err != nil {
		// gVisor dial failures can surface as a net.Conn containing a typed nil.
		conn = nil
	}
	return d.streams.finishOpen(conn, operationError(operationCtx, err))
}

// Drain rejects new streams and waits for existing streams to close.
func (d *Dialer) Drain(ctx context.Context) error {
	if err := d.lifecycle.beginDrain(); err != nil {
		return err
	}
	return d.streams.drain(ctx)
}

// Close terminally stops the dialer, cancels context-aware calls, and waits for
// admitted operations.
func (d *Dialer) Close() error {
	d.closeOnce.Do(func() {
		d.lifecycle.close()
		d.streams.close()
		d.operations.closeAndWait()
		if d.client != nil {
			d.closeErr = d.client.Close()
		}
	})
	return d.closeErr
}
