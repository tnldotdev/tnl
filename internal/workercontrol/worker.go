package workercontrol

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	yamux "github.com/libp2p/go-yamux/v5"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/relay"
	"github.com/tnldotdev/tnl/internal/worker"
	"github.com/tnldotdev/tnl/pkg/protocol/workerv1"
	"tailscale.com/types/key"
)

type WorkerConfig struct {
	URL                   string
	Token                 credentials.WorkerToken
	Worker                worker.RouteWorker
	HTTPClient            *http.Client
	MaxStreams            int
	DrainTime             time.Duration
	RouteTime             time.Duration
	OnError               func(error)
	OnSessionEstablished  func(SessionRole)
	OnSessionDisconnected func(SessionRole, DisconnectReason)
}

func RunWorker(ctx context.Context, config WorkerConfig) error {
	if config.URL == "" || config.Token == "" || config.Worker == nil {
		return errors.New("workercontrol: URL, token, and worker are required")
	}
	if config.MaxStreams <= 0 {
		config.MaxStreams = defaultMaxStreams
	}
	if config.DrainTime <= 0 {
		config.DrainTime = 30 * time.Second
	}
	if config.RouteTime <= 0 {
		config.RouteTime = requestTimeout
	}
	header := make(http.Header)
	header.Set("Authorization", "Bearer "+config.Token.String())
	connection, response, err := websocket.Dial(ctx, config.URL, &websocket.DialOptions{
		HTTPClient:   config.HTTPClient,
		HTTPHeader:   header,
		Subprotocols: []string{workerv1.Subprotocol},
	})
	if err != nil {
		if response != nil {
			return fmt.Errorf("workercontrol: connect: HTTP %d: %w", response.StatusCode, err)
		}
		return fmt.Errorf("workercontrol: connect: %w", err)
	}
	defer connection.CloseNow()
	if connection.Subprotocol() != workerv1.Subprotocol {
		return errors.New("workercontrol: edge omitted worker subprotocol")
	}
	// Keep transport alive long enough to drain after ctx is canceled.
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	network := websocket.NetConn(lifetime, connection, websocket.MessageBinary)
	session, err := yamux.Client(network, muxConfig(config.MaxStreams), nil)
	if err != nil {
		return err
	}
	defer session.Close()
	control, err := session.OpenStream(ctx)
	if err != nil {
		return err
	}
	_ = control.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := workerv1.WriteControl(control, workerv1.Message{Type: workerv1.Hello, RouteCapacity: config.Worker.Capacity().Limit}); err != nil {
		return err
	}
	accepted, err := workerv1.ReadControl(control)
	if err != nil {
		return fmt.Errorf("workercontrol: edge rejected hello: %w", err)
	}
	if accepted.Type != workerv1.HelloAccepted {
		return errors.New("workercontrol: edge rejected hello")
	}
	_ = control.SetDeadline(time.Time{})
	reason := DisconnectInternal
	if config.OnSessionEstablished != nil {
		config.OnSessionEstablished(RoleWorker)
	}
	defer func() {
		if config.OnSessionDisconnected != nil {
			config.OnSessionDisconnected(RoleWorker, reason)
		}
	}()

	running := &workerSession{
		config: config, session: session, control: control,
		routes: make(map[worker.RouteRef]worker.WorkerRoute),
	}
	errC := make(chan error, 2)
	go func() { errC <- running.controlLoop() }()
	go func() { errC <- running.acceptLoop() }()
	select {
	case <-ctx.Done():
		reason = DisconnectShutdown
		return running.shutdown()
	case err := <-errC:
		_ = config.Worker.Close()
		shuttingDown := ctx.Err() != nil
		if shuttingDown {
			reason = DisconnectShutdown
		} else {
			reason = disconnectReason(err)
		}
		if shuttingDown || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
}

type workerSession struct {
	config  WorkerConfig
	session *yamux.Session
	control net.Conn

	writeMu   sync.Mutex
	mu        sync.RWMutex
	routes    map[worker.RouteRef]worker.WorkerRoute
	commands  sync.WaitGroup
	commandMu sync.Mutex
	draining  atomic.Bool
}

func (s *workerSession) controlLoop() error {
	for {
		message, err := workerv1.ReadControl(s.control)
		if err != nil {
			return err
		}
		switch message.Type {
		case workerv1.AttachRoute:
			if !s.startCommand() {
				s.sendError(routeRef(message.Route), workerv1.RouteCapacityExceeded)
				continue
			}
			go func() {
				defer s.commands.Done()
				s.handleAttach(message)
			}()
		case workerv1.DetachRoute:
			if !s.startCommand() {
				s.write(workerv1.Message{Type: workerv1.RouteDrained, Route: message.Route})
				continue
			}
			go func() {
				defer s.commands.Done()
				s.handleDetach(message)
			}()
		default:
			return fmt.Errorf("workercontrol: unexpected edge message %s", message.Type)
		}
	}
}

func (s *workerSession) acceptLoop() error {
	for {
		stream, err := s.session.AcceptStream()
		if err != nil {
			return err
		}
		go s.handleData(stream)
	}
}

func (s *workerSession) handleAttach(message workerv1.Message) {
	ref := routeRef(message.Route)
	if s.draining.Load() {
		s.sendError(ref, workerv1.RouteCapacityExceeded)
		return
	}
	var tailcatDialerKey key.NodePrivate
	if err := tailcatDialerKey.UnmarshalText([]byte(message.TailcatDialerPrivateKey)); err != nil || tailcatDialerKey.IsZero() {
		s.sendError(ref, workerv1.InvalidMessage)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.config.RouteTime)
	defer cancel()
	owned, err := s.config.Worker.Attach(ctx, worker.Assignment{
		RouteRef: ref,
		Endpoint: *message.PublisherTransport,
		Key:      tailcatDialerKey,
	})
	if err != nil {
		s.sendError(ref, workerError(err))
		return
	}
	s.mu.Lock()
	s.routes[ref] = owned
	s.mu.Unlock()
	s.write(workerv1.Message{Type: workerv1.RouteReady, Route: protocolRef(ref)})
}

func (s *workerSession) handleDetach(message workerv1.Message) {
	ref := routeRef(message.Route)
	s.mu.Lock()
	owned := s.routes[ref]
	delete(s.routes, ref)
	s.mu.Unlock()
	if owned != nil {
		ctx, cancel := context.WithTimeout(context.Background(), s.config.RouteTime)
		_ = owned.Drain(ctx)
		cancel()
		_ = owned.Close()
	}
	s.write(workerv1.Message{Type: workerv1.RouteDrained, Route: protocolRef(ref)})
}

func (s *workerSession) handleData(stream *yamux.Stream) {
	defer stream.Close()
	if s.draining.Load() {
		_ = stream.Reset()
		return
	}
	_ = stream.SetReadDeadline(time.Now().Add(handshakeTimeout))
	header, err := workerv1.ReadDataHeader(stream)
	_ = stream.SetReadDeadline(time.Time{})
	if err != nil {
		_ = stream.Reset()
		s.report(err)
		return
	}
	ref := worker.RouteRef{RouteID: header.RouteID, RouteVersion: header.RouteVersion}
	s.mu.RLock()
	owned := s.routes[ref]
	s.mu.RUnlock()
	if owned == nil {
		_ = stream.Reset()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.config.RouteTime)
	connection, err := owned.Open(ctx)
	cancel()
	if err != nil {
		_ = stream.Reset()
		s.report(err)
		return
	}
	defer connection.Close()
	if _, err := relay.Copy(stream, connection); err != nil {
		s.report(err)
	}
}

func (s *workerSession) shutdown() error {
	if !s.draining.CompareAndSwap(false, true) {
		return nil
	}
	_ = s.write(workerv1.Message{Type: workerv1.WorkerDraining})
	// Serialize Add with Wait so shutdown cannot miss an accepted command.
	s.commandMu.Lock()
	s.commands.Wait()
	s.commandMu.Unlock()
	drainCtx, cancel := context.WithTimeout(context.Background(), s.config.DrainTime)
	drainErr := s.config.Worker.Drain(drainCtx)
	cancel()
	s.mu.Lock()
	routes := make([]worker.RouteRef, 0, len(s.routes))
	for ref := range s.routes {
		routes = append(routes, ref)
	}
	clear(s.routes)
	s.mu.Unlock()
	for _, ref := range routes {
		_ = s.write(workerv1.Message{Type: workerv1.RouteDrained, Route: protocolRef(ref)})
	}
	_ = s.session.GoAway()
	closeErr := s.config.Worker.Close()
	_ = s.session.Close()
	return errors.Join(drainErr, closeErr)
}

func (s *workerSession) startCommand() bool {
	s.commandMu.Lock()
	defer s.commandMu.Unlock()
	if s.draining.Load() {
		return false
	}
	s.commands.Add(1)
	return true
}

func (s *workerSession) write(message workerv1.Message) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return writeControlMessage(s.control, message)
}

func (s *workerSession) sendError(ref worker.RouteRef, code workerv1.ErrorCode) {
	_ = s.write(workerv1.Message{Type: workerv1.Error, Route: protocolRef(ref), Code: code})
}

func (s *workerSession) report(err error) {
	if err != nil && s.config.OnError != nil {
		s.config.OnError(err)
	}
}

func protocolRef(ref worker.RouteRef) *workerv1.RouteRef {
	return &workerv1.RouteRef{RouteID: ref.RouteID, RouteVersion: ref.RouteVersion}
}

func routeRef(ref *workerv1.RouteRef) worker.RouteRef {
	return worker.RouteRef{RouteID: ref.RouteID, RouteVersion: ref.RouteVersion}
}

func workerError(err error) workerv1.ErrorCode {
	switch {
	case errors.Is(err, worker.ErrStaleAssignment):
		return workerv1.StaleRouteVersion
	case errors.Is(err, worker.ErrAtCapacity), errors.Is(err, worker.ErrDraining):
		return workerv1.RouteCapacityExceeded
	default:
		return workerv1.Internal
	}
}
