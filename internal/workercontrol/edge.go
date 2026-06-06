package workercontrol

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
	"github.com/tnldotdev/tnl/internal/worker"
	"github.com/tnldotdev/tnl/pkg/protocol/workerv1"
)

type Registry interface {
	AddWorker(string, worker.RouteWorker) error
	DrainWorker(context.Context, string) error
	RemoveWorker(string)
}

type HubConfig struct {
	Tokens                []credentials.WorkerVerifier
	Registry              Registry
	MaxStreams            int
	MaxSessions           int
	MaxWorkerCapacity     int
	MaxTotalCapacity      int
	DrainTime             time.Duration
	OnError               func(error)
	OnSessionEstablished  func(SessionRole)
	OnSessionDisconnected func(SessionRole, DisconnectReason)
}

type Hub struct {
	config        HubConfig
	mu            sync.Mutex
	sessions      map[credentials.CredentialID]*workerReservation
	totalCapacity int
	closed        bool
}

type workerReservation struct {
	connection *websocket.Conn
	capacity   int
}

func NewHub(config HubConfig) (*Hub, error) {
	if len(config.Tokens) == 0 || config.Registry == nil {
		return nil, errors.New("workercontrol: worker tokens and registry are required")
	}
	if config.MaxStreams <= 0 {
		config.MaxStreams = defaultMaxStreams
	}
	if config.MaxSessions <= 0 {
		config.MaxSessions = defaultMaxSessions
	}
	if config.MaxWorkerCapacity <= 0 {
		config.MaxWorkerCapacity = defaultMaxWorkerCapacity
	}
	if config.MaxTotalCapacity <= 0 {
		config.MaxTotalCapacity = defaultMaxTotalCapacity
	}
	seen := make(map[credentials.CredentialID]struct{}, len(config.Tokens))
	for _, verifier := range config.Tokens {
		if _, exists := seen[verifier.ID()]; exists {
			return nil, errors.New("workercontrol: duplicate worker token")
		}
		seen[verifier.ID()] = struct{}{}
	}
	if config.DrainTime <= 0 {
		config.DrainTime = 30 * time.Second
	}
	return &Hub{config: config, sessions: make(map[credentials.CredentialID]*workerReservation)}, nil
}

func (h *Hub) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token, err := credentials.Bearer(request.Header)
	credentialID, authenticated := h.authenticate(credentials.WorkerToken(token))
	if err != nil || !authenticated {
		response.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(response, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !h.reserve(credentialID) {
		http.Error(response, "worker session limit reached", http.StatusTooManyRequests)
		return
	}
	defer h.release(credentialID)
	connection, err := websocket.Accept(response, request, &websocket.AcceptOptions{
		Subprotocols: []string{workerv1.Subprotocol},
	})
	if err != nil {
		return
	}
	defer connection.CloseNow()
	if !h.bind(credentialID, connection) {
		return
	}
	if connection.Subprotocol() != workerv1.Subprotocol {
		_ = connection.Close(websocket.StatusPolicyViolation, "subprotocol required")
		return
	}

	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	network := websocket.NetConn(lifetime, connection, websocket.MessageBinary)
	session, err := yamux.Server(network, muxConfig(1), nil)
	if err != nil {
		h.report(err)
		return
	}
	defer session.Close()
	control, err := session.AcceptStream()
	if err != nil {
		h.report(err)
		return
	}
	_ = control.SetDeadline(time.Now().Add(handshakeTimeout))
	hello, err := workerv1.ReadControl(control)
	if err != nil {
		h.report(fmt.Errorf("workercontrol: invalid worker hello: %w", err))
		return
	}
	if hello.Type != workerv1.Hello {
		h.report(errors.New("workercontrol: invalid worker hello"))
		return
	}
	if !h.claimCapacity(credentialID, hello.Capacity) {
		_ = workerv1.WriteControl(control, workerv1.Message{Type: workerv1.Error, Code: workerv1.AtCapacity})
		return
	}
	if err := workerv1.WriteControl(control, workerv1.Message{Type: workerv1.Accepted}); err != nil {
		h.report(err)
		return
	}
	_ = control.SetDeadline(time.Time{})
	reason := DisconnectInternal
	h.sessionEstablished(RoleEdge)
	defer func() {
		if h.isClosed() {
			reason = DisconnectShutdown
		}
		h.sessionDisconnected(RoleEdge, reason)
	}()

	id, err := sessionID()
	if err != nil {
		h.report(err)
		return
	}
	worker := newRemoteWorker(session, control, hello.Capacity, h.config.MaxStreams)
	if err := h.config.Registry.AddWorker(id, worker); err != nil {
		h.report(err)
		return
	}
	worker.onDraining = func() {
		ctx, cancel := context.WithTimeout(context.Background(), h.config.DrainTime)
		defer cancel()
		if err := h.config.Registry.DrainWorker(ctx, id); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			h.report(err)
		}
	}
	err = worker.readLoop()
	h.config.Registry.RemoveWorker(id)
	_ = worker.Close()
	if h.isClosed() {
		reason = DisconnectShutdown
	} else {
		reason = disconnectReason(err)
	}
	if !errors.Is(err, net.ErrClosed) {
		h.report(err)
	}
}

func (h *Hub) Close() {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	connections := make([]*websocket.Conn, 0, len(h.sessions))
	for _, reservation := range h.sessions {
		if reservation.connection != nil {
			connections = append(connections, reservation.connection)
		}
	}
	h.mu.Unlock()
	for _, connection := range connections {
		_ = connection.CloseNow()
	}
}

func (h *Hub) reserve(id credentials.CredentialID) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || len(h.sessions) >= h.config.MaxSessions || h.sessions[id] != nil {
		return false
	}
	h.sessions[id] = &workerReservation{}
	return true
}

func (h *Hub) bind(id credentials.CredentialID, connection *websocket.Conn) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	reservation := h.sessions[id]
	if h.closed || reservation == nil {
		return false
	}
	reservation.connection = connection
	return true
}

func (h *Hub) claimCapacity(id credentials.CredentialID, capacity int) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	reservation := h.sessions[id]
	if reservation == nil || capacity <= 0 || capacity > h.config.MaxWorkerCapacity ||
		h.totalCapacity+capacity > h.config.MaxTotalCapacity {
		return false
	}
	reservation.capacity = capacity
	h.totalCapacity += capacity
	return true
}

func (h *Hub) release(id credentials.CredentialID) {
	h.mu.Lock()
	if reservation := h.sessions[id]; reservation != nil {
		h.totalCapacity -= reservation.capacity
		delete(h.sessions, id)
	}
	h.mu.Unlock()
}

func (h *Hub) isClosed() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closed
}

func (h *Hub) authenticate(token credentials.WorkerToken) (credentials.CredentialID, bool) {
	var matchedID credentials.CredentialID
	matched := 0
	// Run every verifier so token position does not affect timing.
	for _, verifier := range h.config.Tokens {
		if verifier.Matches(token) {
			matchedID = verifier.ID()
			matched++
		}
	}
	return matchedID, matched == 1
}

func (h *Hub) report(err error) {
	if err != nil && h.config.OnError != nil {
		h.config.OnError(err)
	}
}

func (h *Hub) sessionEstablished(role SessionRole) {
	if h.config.OnSessionEstablished != nil {
		h.config.OnSessionEstablished(role)
	}
}

func (h *Hub) sessionDisconnected(role SessionRole, reason DisconnectReason) {
	if h.config.OnSessionDisconnected != nil {
		h.config.OnSessionDisconnected(role, reason)
	}
}

func sessionID() (string, error) {
	var material [16]byte
	if _, err := rand.Read(material[:]); err != nil {
		return "", err
	}
	return "worker_" + hex.EncodeToString(material[:]), nil
}

type pendingResponse struct {
	message workerv1.Message
	err     error
}

type remoteWorker struct {
	session    *yamux.Session
	control    net.Conn
	capacity   int
	maxStreams int

	writeMu sync.Mutex
	mu      sync.Mutex
	routes  map[string]*remoteRoute
	pending map[worker.RouteRef]chan pendingResponse
	changed chan struct{}

	attaching      int
	streams        int
	draining       bool
	workerDraining bool
	closed         bool
	closeOnce      sync.Once
	onDraining     func()
}

func newRemoteWorker(session *yamux.Session, control net.Conn, capacity, maxStreams int) *remoteWorker {
	return &remoteWorker{
		session: session, control: control, capacity: capacity, maxStreams: maxStreams,
		routes: make(map[string]*remoteRoute), pending: make(map[worker.RouteRef]chan pendingResponse),
		changed: make(chan struct{}),
	}
}

func (o *remoteWorker) Attach(ctx context.Context, assignment worker.Assignment) (worker.WorkerRoute, error) {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return nil, net.ErrClosed
	}
	if o.draining {
		o.mu.Unlock()
		return nil, worker.ErrDraining
	}
	if current := o.routes[assignment.RouteID]; current != nil {
		if current.ref.Version == assignment.Version {
			o.mu.Unlock()
			return current, nil
		}
		if current.ref.Version > assignment.Version {
			o.mu.Unlock()
			return nil, worker.ErrStaleAssignment
		}
	}
	if len(o.routes)+o.attaching >= o.capacity {
		o.mu.Unlock()
		return nil, worker.ErrAtCapacity
	}
	o.attaching++
	o.mu.Unlock()
	defer func() {
		o.mu.Lock()
		o.attaching--
		o.notifyLocked()
		o.mu.Unlock()
	}()

	privateKey, err := assignment.Key.MarshalText()
	if err != nil {
		return nil, err
	}
	ref := assignment.RouteRef
	response, err := o.request(ctx, workerv1.Message{
		Type:             workerv1.AttachRoute,
		Route:            &workerv1.RouteRef{RouteID: ref.RouteID, Version: ref.Version},
		Endpoint:         &assignment.Endpoint,
		WorkerPrivateKey: string(privateKey),
	})
	if err != nil {
		return nil, err
	}
	if response.Type != workerv1.RouteReady {
		return nil, errors.New("workercontrol: unexpected attach response")
	}
	route := &remoteRoute{worker: o, ref: ref}
	// The request ran unlocked; reject routes that raced with drain or shutdown.
	o.mu.Lock()
	if o.closed || o.draining {
		o.mu.Unlock()
		o.discard(ref)
		return nil, worker.ErrDraining
	}
	previous := o.routes[ref.RouteID]
	o.routes[ref.RouteID] = route
	o.notifyLocked()
	o.mu.Unlock()
	if previous != nil {
		previous.markClosed()
		o.discard(previous.ref)
	}
	return route, nil
}

func (o *remoteWorker) Capacity() worker.Capacity {
	o.mu.Lock()
	defer o.mu.Unlock()
	return worker.Capacity{Active: len(o.routes) + o.attaching, Limit: o.capacity, Draining: o.draining || o.closed}
}

func (o *remoteWorker) Drain(ctx context.Context) error {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return net.ErrClosed
	}
	o.draining = true
	workerInitiated := o.workerDraining
	routes := make([]*remoteRoute, 0, len(o.routes))
	for _, route := range o.routes {
		routes = append(routes, route)
	}
	o.notifyLocked()
	o.mu.Unlock()

	if !workerInitiated {
		errorsByRoute := make(chan error, len(routes))
		var group sync.WaitGroup
		for _, route := range routes {
			group.Add(1)
			go func() {
				defer group.Done()
				if err := route.stop(ctx); err != nil {
					errorsByRoute <- err
				}
			}()
		}
		group.Wait()
		close(errorsByRoute)
		var result error
		for err := range errorsByRoute {
			result = errors.Join(result, err)
		}
		return result
	}

	// Worker-initiated drains report RouteDrained as local routes finish.
	for {
		o.mu.Lock()
		if len(o.routes) == 0 {
			o.mu.Unlock()
			return nil
		}
		changed := o.changed
		o.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (o *remoteWorker) Close() error {
	o.closeOnce.Do(func() {
		o.mu.Lock()
		o.closed = true
		o.draining = true
		for _, pending := range o.pending {
			pending <- pendingResponse{err: net.ErrClosed}
			close(pending)
		}
		clear(o.pending)
		for _, route := range o.routes {
			route.markClosed()
		}
		clear(o.routes)
		o.notifyLocked()
		o.mu.Unlock()
		_ = o.control.Close()
		_ = o.session.Close()
	})
	return nil
}

func (o *remoteWorker) readLoop() error {
	for {
		message, err := workerv1.ReadControl(o.control)
		if err != nil {
			return err
		}
		if message.Type == workerv1.WorkerDraining {
			o.mu.Lock()
			first := !o.workerDraining
			o.workerDraining = true
			o.draining = true
			o.notifyLocked()
			o.mu.Unlock()
			if first && o.onDraining != nil {
				// DrainWorker waits for replies consumed by this loop.
				go o.onDraining()
			}
			continue
		}
		if message.Route == nil {
			return errors.New("workercontrol: response omitted route")
		}
		ref := worker.RouteRef{RouteID: message.Route.RouteID, Version: message.Route.Version}
		o.mu.Lock()
		pending := o.pending[ref]
		if pending != nil {
			delete(o.pending, ref)
		}
		o.mu.Unlock()
		if pending != nil {
			pending <- pendingResponse{message: message}
			close(pending)
			continue
		}
		if message.Type == workerv1.RouteDrained {
			o.markDrained(ref)
			continue
		}
		if message.Type == workerv1.RouteReady {
			// A timed-out attach may finish remotely; detach the orphaned route.
			if err := o.write(workerv1.Message{Type: workerv1.DetachRoute, Route: message.Route}); err != nil {
				return err
			}
			continue
		}
		if message.Type == workerv1.Error {
			continue
		}
		return fmt.Errorf("workercontrol: unexpected %s response", message.Type)
	}
}

func (o *remoteWorker) request(ctx context.Context, message workerv1.Message) (workerv1.Message, error) {
	ref := worker.RouteRef{RouteID: message.Route.RouteID, Version: message.Route.Version}
	response := make(chan pendingResponse, 1)
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return workerv1.Message{}, net.ErrClosed
	}
	if _, exists := o.pending[ref]; exists {
		o.mu.Unlock()
		return workerv1.Message{}, errors.New("workercontrol: route operation already pending")
	}
	o.pending[ref] = response
	o.mu.Unlock()
	if err := o.write(message); err != nil {
		o.removePending(ref, response)
		return workerv1.Message{}, err
	}
	select {
	case result := <-response:
		if result.err != nil {
			return workerv1.Message{}, result.err
		}
		if result.message.Type == workerv1.Error {
			return workerv1.Message{}, remoteError(result.message.Code)
		}
		return result.message, nil
	case <-ctx.Done():
		o.removePending(ref, response)
		return workerv1.Message{}, ctx.Err()
	}
}

func (o *remoteWorker) write(message workerv1.Message) error {
	o.writeMu.Lock()
	defer o.writeMu.Unlock()
	return workerv1.WriteControl(o.control, message)
}

func (o *remoteWorker) removePending(ref worker.RouteRef, response chan pendingResponse) {
	o.mu.Lock()
	if o.pending[ref] == response {
		delete(o.pending, ref)
	}
	o.mu.Unlock()
}

func (o *remoteWorker) discard(ref worker.RouteRef) {
	_ = o.write(workerv1.Message{Type: workerv1.DetachRoute, Route: protocolRef(ref)})
}

func (o *remoteWorker) open(ctx context.Context, route *remoteRoute) (net.Conn, error) {
	o.mu.Lock()
	ready := o.routes[route.ref.RouteID] == route && !o.draining && !o.closed
	atCapacity := ready && o.streams >= o.maxStreams
	if ready && !atCapacity {
		o.streams++
	}
	o.mu.Unlock()
	if !ready {
		return nil, worker.ErrDraining
	}
	if atCapacity {
		return nil, worker.ErrAtCapacity
	}
	stream, err := o.session.OpenStream(ctx)
	if err != nil {
		o.releaseStream()
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetWriteDeadline(deadline)
	}
	if err := workerv1.WriteDataHeader(stream, workerv1.DataHeader{RouteID: route.ref.RouteID, Version: route.ref.Version}); err != nil {
		_ = stream.Reset()
		o.releaseStream()
		return nil, err
	}
	_ = stream.SetWriteDeadline(time.Time{})
	return &countedStream{Conn: stream, release: o.releaseStream}, nil
}

func (o *remoteWorker) releaseStream() {
	o.mu.Lock()
	o.streams--
	o.mu.Unlock()
}

type countedStream struct {
	net.Conn
	release func()
	once    sync.Once
}

func (s *countedStream) Close() error {
	err := s.Conn.Close()
	s.once.Do(s.release)
	return err
}

func (s *countedStream) CloseRead() error {
	if closer, ok := s.Conn.(interface{ CloseRead() error }); ok {
		return closer.CloseRead()
	}
	return errors.ErrUnsupported
}

func (s *countedStream) CloseWrite() error {
	if closer, ok := s.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return errors.ErrUnsupported
}

func (o *remoteWorker) detach(ctx context.Context, route *remoteRoute) error {
	message, err := o.request(ctx, workerv1.Message{
		Type:  workerv1.DetachRoute,
		Route: &workerv1.RouteRef{RouteID: route.ref.RouteID, Version: route.ref.Version},
	})
	if err == nil && message.Type != workerv1.RouteDrained {
		err = errors.New("workercontrol: unexpected detach response")
	}
	o.markDrained(route.ref)
	return err
}

func (o *remoteWorker) markDrained(ref worker.RouteRef) {
	o.mu.Lock()
	route := o.routes[ref.RouteID]
	if route != nil && route.ref == ref {
		delete(o.routes, ref.RouteID)
		route.markClosed()
		o.notifyLocked()
	}
	o.mu.Unlock()
}

func (o *remoteWorker) notifyLocked() {
	close(o.changed)
	o.changed = make(chan struct{})
}

type remoteRoute struct {
	worker  *remoteWorker
	ref     worker.RouteRef
	stopped atomic.Bool
}

func (r *remoteRoute) Open(ctx context.Context) (net.Conn, error) {
	if r.stopped.Load() {
		return nil, net.ErrClosed
	}
	return r.worker.open(ctx, r)
}

func (r *remoteRoute) Drain(ctx context.Context) error { return r.stop(ctx) }

func (r *remoteRoute) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	return r.stop(ctx)
}

func (r *remoteRoute) stop(ctx context.Context) error {
	if !r.stopped.CompareAndSwap(false, true) {
		return nil
	}
	return r.worker.detach(ctx, r)
}

func (r *remoteRoute) markClosed() {
	r.stopped.Store(true)
}

func remoteError(code workerv1.ErrorCode) error {
	switch code {
	case workerv1.StaleAssignment:
		return worker.ErrStaleAssignment
	case workerv1.AtCapacity:
		return worker.ErrAtCapacity
	default:
		return errors.New("workercontrol: worker rejected operation")
	}
}
