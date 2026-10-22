package relay

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/streamcopy"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type privateConnection struct {
	ref   tunnelv1.PrivatePublisherConnectionRef
	lease relayv1.RelayLease
	paths *PublisherConnection
}

// PrivateRegistry contains only exact locally claimed private assignments.
// public URL references cannot select entries from this registry.
type PrivateRegistry struct {
	observer    OperationObserver
	mu          sync.Mutex
	connections map[string]*privateConnection
	claims      map[string]*privateClaim
	closed      bool
}

func NewPrivateRegistry() *PrivateRegistry {
	return &PrivateRegistry{connections: make(map[string]*privateConnection)}
}

// Instrument configures observation before the registry begins serving work.
func (r *PrivateRegistry) Instrument(observer OperationObserver) { r.observer = observer }

// reserve holds local ownership from before control's claim through its final
// disconnect. response-loss retries use the same assignment and process lease;
// a duplicate handshake must never reach control or clean up the owner's claim.
func (r *PrivateRegistry) reserve(c *privateClaim) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return &tunnel.ProtocolError{Code: tunnelv1.DrainingPublisherConnection}
	}
	if r.claims[c.ref.PublisherConnectionID] != nil || r.connections[c.ref.PublisherConnectionID] != nil {
		return &tunnel.ProtocolError{Code: tunnelv1.DuplicatePublisherConnection}
	}
	for _, old := range r.claims {
		if old.ref.PrivateRunID == c.ref.PrivateRunID && old.ref.ConnectionSlot == c.ref.ConnectionSlot && old.ref.ConnectionAssignmentRevision >= c.ref.ConnectionAssignmentRevision {
			return &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
		}
	}
	if r.claims == nil {
		r.claims = make(map[string]*privateClaim)
	}
	r.claims[c.ref.PublisherConnectionID] = c
	return nil
}

func (r *PrivateRegistry) release(c *privateClaim) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.claims[c.ref.PublisherConnectionID] == c {
		delete(r.claims, c.ref.PublisherConnectionID)
	}
}

func (r *PrivateRegistry) insert(c *privateConnection) error {
	r.mu.Lock()
	if r.closed || r.connections[c.ref.PublisherConnectionID] != nil {
		r.mu.Unlock()
		return errors.New("relay: private assignment already connected or draining")
	}
	var replaced *privateConnection
	for _, old := range r.connections {
		if old.ref.PrivateServiceID == c.ref.PrivateServiceID && old.ref.PrivateRunID == c.ref.PrivateRunID && old.ref.ConnectionSlot == c.ref.ConnectionSlot {
			if old.ref.ConnectionAssignmentRevision >= c.ref.ConnectionAssignmentRevision {
				r.mu.Unlock()
				return &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
			}
			replaced = old
			break
		}
	}
	// control checks shared public/private process capacity under its lease lock.
	if replaced != nil {
		delete(r.connections, replaced.ref.PublisherConnectionID)
	}
	r.connections[c.ref.PublisherConnectionID] = c
	if replaced == nil {
		if observer, ok := r.observer.(interface{ AddRegisteredPublisherConnections(int) }); ok {
			observer.AddRegisteredPublisherConnections(1)
		}
	}
	r.mu.Unlock()
	if replaced != nil {
		_ = replaced.paths.Close()
	}
	return nil
}

func (r *PrivateRegistry) remove(c *privateConnection) {
	r.mu.Lock()
	if r.connections[c.ref.PublisherConnectionID] == c {
		delete(r.connections, c.ref.PublisherConnectionID)
		if observer, ok := r.observer.(interface{ AddRegisteredPublisherConnections(int) }); ok {
			observer.AddRegisteredPublisherConnections(-1)
		}
	}
	r.mu.Unlock()
	_ = c.paths.Close()
}

func (r *PrivateRegistry) candidate(h tunnelv1.PrivateForwardingHeader, lease relayv1.RelayLease, now time.Time) (*privateConnection, bool) {
	if h.Validate() != nil || !h.ExpiresAt.After(now) || !h.LeaseExpiresAt.After(now) || lease.Draining || !lease.LeaseExpiresAt.After(now) ||
		h.RelayServiceID != lease.RelayServiceId || h.RelayID != lease.RelayId || h.RelayRunID != lease.RelayRunId || h.RelayLeaseRevision != uint64(lease.RelayLeaseRevision) {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.connections[h.PublisherConnectionID]
	if c == nil || r.closed || c.ref.PrivateServiceID != h.PrivateServiceID || c.ref.PrivateRunID != h.PrivateRunID || c.ref.RunNumber != h.RunNumber ||
		c.ref.ConnectionSlot != h.ConnectionSlot || c.ref.ConnectionAssignmentRevision != h.ConnectionAssignmentRevision || c.ref.RelayServiceID != h.RelayServiceID ||
		c.lease.RelayRunId != lease.RelayRunId || c.lease.RelayLeaseRevision != lease.RelayLeaseRevision {
		return nil, false
	}
	return c, true
}

func (r *PrivateRegistry) snapshot() []*privateConnection {
	r.mu.Lock()
	defer r.mu.Unlock()
	var entries []*privateConnection
	for _, c := range r.connections {
		entries = append(entries, c)
	}
	return entries
}

func (r *PrivateRegistry) Load() (connections, streams int64) {
	for _, c := range r.snapshot() {
		connections++
		c.paths.mu.Lock()
		streams += int64(c.paths.opening + len(c.paths.streams))
		c.paths.mu.Unlock()
	}
	return
}

func (r *PrivateRegistry) Close() error {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	var result error
	for _, c := range r.snapshot() {
		result = errors.Join(result, c.paths.Close())
	}
	return result
}

func (r *PrivateRegistry) Drain(ctx context.Context) error {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	var group sync.WaitGroup
	var mu sync.Mutex
	var result error
	for _, c := range r.snapshot() {
		group.Go(func() { err := c.paths.Drain(ctx); mu.Lock(); result = errors.Join(result, err); mu.Unlock() })
	}
	group.Wait()
	return result
}

type PrivatePublisherTarget struct {
	Control  *Controller
	Registry *PrivateRegistry
}
type PrivatePublisherAcceptor struct {
	Select func(string) (PrivatePublisherTarget, bool)
}

type privateClaim struct {
	target PrivatePublisherTarget
	ref    tunnelv1.PrivatePublisherConnectionRef
	lease  relayv1.RelayLease
}

func (a *PrivatePublisherAcceptor) claim(ctx context.Context, message tunnelv1.Message) (*privateClaim, error) {
	if a == nil || a.Select == nil || message.Role != tunnelv1.Publisher || message.PrivateConnection == nil {
		return nil, &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	}
	ref := *message.PrivateConnection
	target, ok := a.Select(ref.RelayServiceID)
	if !ok || target.Control == nil || target.Registry == nil {
		return nil, &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	}
	claim := &privateClaim{target: target, ref: ref}
	if err := target.Registry.reserve(claim); err != nil {
		return nil, err
	}
	lease, err := target.Control.privateClaim(ctx, ref, message.Credential)
	if err != nil {
		target.Registry.release(claim)
		code := ControlErrorCode(err)
		var direct *tunnelPrivateControlError
		if errors.As(err, &direct) {
			code = direct.code
		}
		return nil, errors.Join(err, &tunnel.ProtocolError{Code: code})
	}
	claim.lease = lease
	return claim, nil
}

func (c *privateClaim) serve(ctx context.Context, session *tunnel.Session, acceptor *PublisherAcceptor, finishAdmission func(error)) (result error) {
	defer c.target.Registry.release(c)
	ready := false
	unexpected := false
	defer func() {
		if !ready {
			finishAdmission(result)
		}
		if ready {
			acceptor.readyDelta(-1)
			acceptor.connectionExited(unexpected)
		}
	}()
	defer func() {
		finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		observe := startOperation(finish, acceptor.observer, "RelayDisconnectPublisherConnection")
		err := c.target.Control.privateTransition(finish, c.ref, c.lease, true)
		observe(err)
		result = errors.Join(result, err)
	}()
	if session == nil {
		return errors.New("relay: private handshake failed after claim")
	}
	paths := &PublisherConnection{session: session, streams: make(map[*trackedConn]struct{}), changed: make(chan struct{})}
	connection := &privateConnection{ref: c.ref, lease: c.lease, paths: paths}
	if err := c.target.Registry.insert(connection); err != nil {
		var protocol *tunnel.ProtocolError
		if errors.As(err, &protocol) && protocol.Code == tunnelv1.CapacityExceeded {
			acceptor.capacity()
		}
		_ = session.Close()
		return err
	}
	defer c.target.Registry.remove(connection)
	if err := c.target.Control.privateTransition(ctx, c.ref, c.lease, false); err != nil {
		return err
	}
	ready = true
	acceptor.readyDelta(1)
	finishAdmission(nil)
	stop := context.AfterFunc(ctx, func() { _ = session.Close() })
	defer stop()
	err := session.HandlePublisherDrain(ctx, paths.Drain)
	unexpected = err != nil && ctx.Err() == nil && !errors.Is(err, net.ErrClosed)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, muxsession.ErrClosed) || errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
	select {
	case <-ctx.Done():
		return nil
	case <-session.Done():
		return nil
	}
}

func (a *ForwardingAcceptor) forwardPrivate(ctx context.Context, incoming *tunnel.IncomingInternalForwardingStream) (retErr error) {
	ctx, endSpan := observability.Start(ctx, "relay.open_private_visitor_stream")
	observability.Visitor(ctx, incoming.PrivateHeader.VisitorConnectionID)
	finishOpen := startOperation(ctx, a.observer, "RelayOpenVisitorStream")
	opened := false
	var rejected error
	defer func() {
		if !opened {
			err := errors.Join(retErr, rejected)
			finishOpen(err)
			endSpan(err)
		}
	}()
	defer incoming.Stream.Close()
	if a.private == nil {
		rejected = &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
		return incoming.Reject(tunnelv1.Unauthenticated)
	}
	if !a.acquireStream() {
		rejected = &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
		return incoming.Reject(tunnelv1.CapacityExceeded)
	}
	defer a.releaseStream()
	header := *incoming.PrivateHeader
	connection, ok := a.private.candidate(header, a.currentLease(), a.now())
	if !ok {
		a.streamRejected("stale_assignment")
		rejected = &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
		return incoming.Reject(tunnelv1.StaleConnectionAssignment)
	}
	if err := connection.paths.beginOpen(); err != nil {
		a.streamRejected("publisher_unavailable")
		rejected = err
		return incoming.Reject(tunnelv1.DrainingPublisherConnection)
	}
	stream, err := connection.paths.session.OpenPrivateForwardingStream(ctx, header)
	publisher, err := connection.paths.finishOpen(stream, err)
	if err != nil {
		a.streamRejected("publisher_unavailable")
		return errors.Join(incoming.Reject(tunnelv1.Unavailable), err)
	}
	defer publisher.Close()
	if _, ok := a.private.candidate(header, a.currentLease(), a.now()); !ok {
		a.streamRejected("stale_assignment")
		rejected = &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
		return incoming.Reject(tunnelv1.StaleConnectionAssignment)
	}
	if err := incoming.Accept(); err != nil {
		return err
	}
	opened = true
	finishOpen(nil)
	endSpan(nil)
	stop := context.AfterFunc(ctx, func() { _ = incoming.Stream.Close(); _ = publisher.Close() })
	defer stop()
	copyDone, watchDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-connection.paths.session.Done():
			// losing the carrier is not an application half-close. reset the
			// ingress stream so an idle TLS visitor cannot wait for more bytes
			// on a publisher path that no longer exists.
			_ = incoming.Stream.Reset(1)
			_ = publisher.Close()
		case <-copyDone:
		case <-ctx.Done():
		}
	}()
	defer func() { close(copyDone); <-watchDone }()
	// ingress alone creates PROXY v2. relay copies it and every following
	// visitor byte unchanged, once, through this exact publisher stream.
	_, finishForward := observability.Start(ctx, "relay.forward_private_visitor")
	copied, err := streamcopy.Copy(incoming.Stream, publisher)
	finishForward(err)
	if observer, ok := a.observer.(interface {
		ObserveRelayTransfer(string, int64, int64, error)
	}); ok {
		observer.ObserveRelayTransfer("managed_service", copied.LeftToRight, copied.RightToLeft, err)
	}
	return err
}
