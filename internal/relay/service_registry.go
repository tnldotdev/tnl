package relay

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type serviceConnection struct {
	ref     tunnelv1.ServicePublisherConnectionRef
	lease   relayv1.RelayLease
	paths   *streamLifetime
	packets *connectorPacketSession
}

type RegistryObserver interface {
	OperationObserver
	AddRegisteredPublisherConnections(int)
}

// ServiceRegistry contains exact locally claimed service assignments for every protocol.
type ServiceRegistry struct {
	observer    RegistryObserver
	mu          sync.Mutex
	connections map[string]*serviceConnection
	claims      map[string]*publisherClaim
	draining    bool
	closed      bool
	closeOnce   sync.Once
	closeErr    error
}

func NewServiceRegistry() *ServiceRegistry {
	return &ServiceRegistry{connections: make(map[string]*serviceConnection)}
}

// Instrument configures observation before the registry begins serving work.
func (r *ServiceRegistry) Instrument(observer RegistryObserver) { r.observer = observer }

// reserve holds local ownership from before control's claim through its final
// disconnect. response-loss retries use the same assignment and process lease;
// a duplicate handshake must never reach control or clean up the owner's claim.
func (r *ServiceRegistry) reserve(c *publisherClaim) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.draining {
		return &tunnel.ProtocolError{Code: tunnelv1.DrainingPublisherConnection}
	}
	if r.claims[c.ref.PublisherConnectionID] != nil || r.connections[c.ref.PublisherConnectionID] != nil {
		return &tunnel.ProtocolError{Code: tunnelv1.DuplicatePublisherConnection}
	}
	for _, old := range r.claims {
		if old.ref.ServiceRunID == c.ref.ServiceRunID && old.ref.ConnectionSlot == c.ref.ConnectionSlot && old.ref.ConnectionAssignmentRevision >= c.ref.ConnectionAssignmentRevision {
			return &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
		}
	}
	if r.claims == nil {
		r.claims = make(map[string]*publisherClaim)
	}
	r.claims[c.ref.PublisherConnectionID] = c
	return nil
}

func (r *ServiceRegistry) release(c *publisherClaim) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.claims[c.ref.PublisherConnectionID] == c {
		delete(r.claims, c.ref.PublisherConnectionID)
	}
}

func (r *ServiceRegistry) insert(c *serviceConnection) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return net.ErrClosed
	}
	if r.draining {
		r.mu.Unlock()
		return ErrDraining
	}
	if r.connections[c.ref.PublisherConnectionID] != nil {
		r.mu.Unlock()
		return &tunnel.ProtocolError{Code: tunnelv1.DuplicatePublisherConnection}
	}
	var replaced *serviceConnection
	for _, old := range r.connections {
		if old.ref.ServiceID == c.ref.ServiceID && old.ref.ServiceRunID == c.ref.ServiceRunID && old.ref.ConnectionSlot == c.ref.ConnectionSlot {
			if old.ref.ConnectionAssignmentRevision >= c.ref.ConnectionAssignmentRevision {
				r.mu.Unlock()
				return &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
			}
			replaced = old
			break
		}
	}
	// control checks process capacity under its lease lock.
	if replaced != nil {
		delete(r.connections, replaced.ref.PublisherConnectionID)
	}
	r.connections[c.ref.PublisherConnectionID] = c
	if replaced == nil {
		if r.observer != nil {
			r.observer.AddRegisteredPublisherConnections(1)
		}
	}
	r.mu.Unlock()
	if replaced != nil {
		if replaced.packets != nil {
			replaced.packets.Close()
		}
		_ = replaced.paths.Close()
	}
	return nil
}

func (r *ServiceRegistry) remove(c *serviceConnection) error {
	r.mu.Lock()
	if r.connections[c.ref.PublisherConnectionID] == c {
		delete(r.connections, c.ref.PublisherConnectionID)
		if r.observer != nil {
			r.observer.AddRegisteredPublisherConnections(-1)
		}
	}
	r.mu.Unlock()
	if c.packets != nil {
		c.packets.Close()
	}
	return c.paths.Close()
}

func (r *ServiceRegistry) candidate(h tunnelv1.ServiceForwardingHeader, lease relayv1.RelayLease, now time.Time) (*serviceConnection, bool) {
	if h.Validate() != nil || !h.ExpiresAt.After(now) || !h.LeaseExpiresAt.After(now) || lease.Draining || !lease.LeaseExpiresAt.After(now) ||
		h.RelayServiceID != lease.RelayServiceId || h.RelayID != lease.RelayId || h.RelayRunID != lease.RelayRunId || h.RelayLeaseRevision != uint64(lease.RelayLeaseRevision) {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.connections[h.PublisherConnectionID]
	if c == nil || r.closed || r.draining || tunnel.ServiceForwardingRef(h) != c.ref ||
		c.lease.RelayServiceId != lease.RelayServiceId || c.lease.RelayId != lease.RelayId ||
		c.lease.RelayRunId != lease.RelayRunId || c.lease.RelayLeaseRevision != lease.RelayLeaseRevision {
		return nil, false
	}
	return c, true
}

func (r *ServiceRegistry) snapshot() []*serviceConnection {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.snapshotLocked()
}

func (r *ServiceRegistry) snapshotLocked() []*serviceConnection {
	var entries []*serviceConnection
	for _, c := range r.connections {
		entries = append(entries, c)
	}
	return entries
}

func (r *ServiceRegistry) Load() (connections, streams int64) {
	for _, c := range r.snapshot() {
		connections++
		c.paths.mu.Lock()
		streams += int64(c.paths.opening + len(c.paths.streams))
		c.paths.mu.Unlock()
	}
	return
}

func (r *ServiceRegistry) Close() error {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed, r.draining = true, true
		connections := r.snapshotLocked()
		clear(r.connections)
		if r.observer != nil {
			r.observer.AddRegisteredPublisherConnections(-len(connections))
		}
		r.mu.Unlock()
		for _, c := range connections {
			if c.packets != nil {
				c.packets.Close()
			}
			r.closeErr = errors.Join(r.closeErr, c.paths.Close())
		}
	})
	return r.closeErr
}

func (r *ServiceRegistry) Drain(ctx context.Context) error {
	finish := startOperation(ctx, r.observer, observability.OpRelayDrain)
	var result error
	defer func() { finish(result) }()
	r.mu.Lock()
	r.draining = true
	r.mu.Unlock()
	var group sync.WaitGroup
	var mu sync.Mutex
	for _, c := range r.snapshot() {
		group.Go(func() {
			if c.packets != nil {
				c.packets.Close()
			}
			err := c.paths.Drain(ctx)
			if err == net.ErrClosed {
				// packet retirement may already be closing this connection. join
				// that close rather than treating a completed drain as a failure.
				err = c.paths.Close()
			}
			mu.Lock()
			result = errors.Join(result, err)
			mu.Unlock()
		})
	}
	group.Wait()
	return result
}

type ServicePublisherTarget struct {
	Control  *Controller
	Registry *ServiceRegistry
}
type publisherClaim struct {
	target ServicePublisherTarget
	ref    tunnelv1.ServicePublisherConnectionRef
	lease  relayv1.RelayLease
}

func (a *PublisherAcceptor) claim(ctx context.Context, message tunnelv1.Message, source netip.Addr) (*publisherClaim, error) {
	if message.Role != tunnelv1.Publisher || message.ServiceConnection == nil {
		return nil, &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	}
	ref := *message.ServiceConnection
	target, ok := a.selectTarget(ref.RelayServiceID)
	if !ok || target.Control == nil || target.Registry == nil {
		return nil, &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	}
	claim := &publisherClaim{target: target, ref: ref}
	if err := target.Registry.reserve(claim); err != nil {
		return nil, err
	}
	lease, err := target.Control.claimServiceConnection(ctx, ref, message.Credential, source)
	if err != nil {
		target.Registry.release(claim)
		code := ControlErrorCode(err)
		var direct *serviceControlError
		if errors.As(err, &direct) {
			code = direct.code
		}
		return nil, errors.Join(err, &tunnel.ProtocolError{Code: code})
	}
	claim.lease = lease
	return claim, nil
}

func (c *publisherClaim) serve(ctx context.Context, session *tunnel.Session, outer muxsession.Session, acceptor *PublisherAcceptor, admissionErr error, finishAdmission func(error)) (result error) {
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
		observe := startOperation(finish, acceptor.observer, observability.OpRelayDisconnectPublisherConnection)
		err := c.target.Control.transitionServiceConnection(finish, c.ref, c.lease, true, unexpected)
		observe(err)
		result = errors.Join(result, err)
	}()
	if admissionErr != nil {
		return admissionErr
	}
	if session == nil {
		return errors.New("relay: publisher handshake failed after claim")
	}
	paths := newStreamLifetime(session)
	connection := &serviceConnection{ref: c.ref, lease: c.lease, paths: paths}
	if acceptor.connector != nil {
		packets, err := newConnectorPacketSession(ctx, outer, serviceStreamReader)
		if err != nil {
			return errors.Join(err, session.Close())
		}
		connection.packets = packets
		defer packets.Close()
	}
	if err := c.target.Registry.insert(connection); err != nil {
		var protocol *tunnel.ProtocolError
		if errors.As(err, &protocol) && protocol.Code == tunnelv1.CapacityExceeded {
			acceptor.capacity()
		}
		return errors.Join(err, session.Close())
	}
	defer func() { result = errors.Join(result, c.target.Registry.remove(connection)) }()
	var peerStreams tunnel.PeerStreamIntroduction
	if connection.packets != nil {
		peerStreams = connection.packets.SharedSession
	}
	dispatcher, err := tunnel.NewServiceStreamDispatcher(ctx, session, peerStreams)
	if err != nil {
		return errors.Join(err, session.Close())
	}
	defer func() { result = errors.Join(result, dispatcher.Close()) }()
	if err := c.target.Control.transitionServiceConnection(ctx, c.ref, c.lease, false, false); err != nil {
		return err
	}
	ready = true
	acceptor.readyDelta(1)
	finishAdmission(nil)
	stop := context.AfterFunc(ctx, func() { _ = session.Close() })
	defer stop()
	err = session.HandlePublisherDrain(ctx, func(drain context.Context) error {
		if connection.packets != nil {
			connection.packets.Close()
		}
		return paths.Drain(drain)
	})
	// drain is an explicit lifecycle fact, not an error classification. failed
	// cleanup must remain visible without turning a planned drain into recovery.
	paths.mu.Lock()
	draining := paths.draining
	paths.mu.Unlock()
	unexpected = err != nil && ctx.Err() == nil && !draining
	if err != nil {
		if failure.Only(err, muxsession.ErrClosed) || failure.Only(err, net.ErrClosed) ||
			ctx.Err() != nil && (failure.Only(err, context.Canceled) || failure.Only(err, context.DeadlineExceeded)) {
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

func (a *ForwardingAcceptor) forwardService(ctx context.Context, incoming *tunnel.IncomingServiceForwardingStream) (retErr error) {
	ctx, endSpan := observability.Start(ctx, "relay.open_connector_visitor_stream")
	observability.Visitor(ctx, incoming.Header.VisitorConnectionID)
	finishOpen := startOperation(ctx, a.observer, observability.OpRelayOpenVisitorStream)
	opened := false
	var rejected error
	defer func() {
		if !opened {
			err := errors.Join(retErr, rejected)
			finishOpen(err)
			endSpan(err)
		}
	}()
	defer func() { retErr = errors.Join(retErr, incoming.Stream().Close()) }()
	if !a.acquireStream() {
		rejected = &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
		return incoming.Reject(tunnelv1.CapacityExceeded)
	}
	defer a.releaseStream()
	header := incoming.Header
	connection, ok := a.registry.candidate(header, a.currentLease(), a.now())
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
	stream, err := connection.paths.session.OpenServiceForwardingStream(ctx, header)
	publisher, err := connection.paths.finishOpen(stream, err)
	if err != nil {
		a.streamRejected("publisher_unavailable")
		return errors.Join(incoming.Reject(tunnelv1.Unavailable), err)
	}
	defer func() { retErr = errors.Join(retErr, publisher.Close()) }()
	unregister, err := connection.paths.session.RegisterServiceCapacity(ctx, header, func(call context.Context) error {
		current, valid := a.registry.candidate(header, a.currentLease(), a.now())
		if !valid || current != connection {
			return &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
		}
		if err := incoming.RequestCapacity(call); err != nil {
			return err
		}
		current, valid = a.registry.candidate(header, a.currentLease(), a.now())
		if !valid || current != connection {
			return &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
		}
		return nil
	})
	if err != nil {
		return errors.Join(err, incoming.Reject(tunnelv1.Unavailable))
	}
	defer unregister()
	if current, ok := a.registry.candidate(header, a.currentLease(), a.now()); !ok || current != connection {
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
	stop := context.AfterFunc(ctx, func() { _ = incoming.Stream().Close(); _ = publisher.Close() })
	defer stop()
	copyDone, watchDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-connection.paths.session.Done():
			// losing the carrier is not an application half-close. reset the
			// ingress stream so an idle TLS visitor cannot wait for more bytes
			// on a publisher path that no longer exists.
			_ = incoming.Stream().Reset(1)
			_ = publisher.Close()
		case <-copyDone:
		case <-ctx.Done():
		}
	}()
	defer func() { close(copyDone); <-watchDone }()
	// ingress alone creates PROXY v2. relay copies it and every following
	// visitor byte unchanged, once, through this exact publisher stream.
	_, finishForward := observability.Start(ctx, "relay.forward_connector_visitor")
	copied, err := streamcopy.Copy(incoming.Stream(), publisher)
	finishForward(err)
	if a.observer != nil {
		a.observer.ObserveRelayTransfer(copied.LeftToRight, copied.RightToLeft, err)
	}
	return err
}
