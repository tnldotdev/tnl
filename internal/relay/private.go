package relay

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
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
	mu          sync.Mutex
	connections map[string]*privateConnection
	closed      bool
}

func NewPrivateRegistry() *PrivateRegistry {
	return &PrivateRegistry{connections: make(map[string]*privateConnection)}
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
	if replaced == nil && int64(len(r.connections)) >= c.lease.ConnectionCapacity {
		r.mu.Unlock()
		return &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
	}
	if replaced != nil {
		delete(r.connections, replaced.ref.PublisherConnectionID)
	}
	r.connections[c.ref.PublisherConnectionID] = c
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
	lease, err := target.Control.privateClaim(ctx, ref, message.Credential)
	if err != nil {
		code := ControlErrorCode(err)
		var direct *tunnelPrivateControlError
		if errors.As(err, &direct) {
			code = direct.code
		}
		return nil, errors.Join(err, &tunnel.ProtocolError{Code: code})
	}
	return &privateClaim{target: target, ref: ref, lease: lease}, nil
}

func (c *privateClaim) serve(ctx context.Context, session *tunnel.Session) (result error) {
	defer func() {
		finish, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		result = errors.Join(result, c.target.Control.privateTransition(finish, c.ref, c.lease, true))
	}()
	if session == nil {
		return errors.New("relay: private handshake failed after claim")
	}
	paths := &PublisherConnection{session: session, streams: make(map[*trackedConn]struct{}), changed: make(chan struct{})}
	connection := &privateConnection{ref: c.ref, lease: c.lease, paths: paths}
	if err := c.target.Registry.insert(connection); err != nil {
		_ = session.Close()
		return err
	}
	defer c.target.Registry.remove(connection)
	if err := c.target.Control.privateTransition(ctx, c.ref, c.lease, false); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { _ = session.Close() })
	defer stop()
	err := session.HandlePublisherDrain(ctx, paths.Drain)
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

func (a *ForwardingAcceptor) forwardPrivate(ctx context.Context, incoming *tunnel.IncomingInternalForwardingStream) error {
	defer incoming.Stream.Close()
	if a.private == nil {
		return incoming.Reject(tunnelv1.Unauthenticated)
	}
	if !a.acquireStream() {
		return incoming.Reject(tunnelv1.CapacityExceeded)
	}
	defer a.releaseStream()
	header := *incoming.PrivateHeader
	connection, ok := a.private.candidate(header, a.currentLease(), a.now())
	if !ok {
		return incoming.Reject(tunnelv1.StaleConnectionAssignment)
	}
	if err := connection.paths.beginOpen(); err != nil {
		return incoming.Reject(tunnelv1.DrainingPublisherConnection)
	}
	opened, err := connection.paths.session.OpenPrivateForwardingStream(ctx, header)
	publisher, err := connection.paths.finishOpen(opened, err)
	if err != nil {
		return errors.Join(incoming.Reject(tunnelv1.Unavailable), err)
	}
	defer publisher.Close()
	if _, ok := a.private.candidate(header, a.currentLease(), a.now()); !ok {
		return incoming.Reject(tunnelv1.StaleConnectionAssignment)
	}
	if err := incoming.Accept(); err != nil {
		return err
	}
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
	_, err = streamcopy.Copy(incoming.Stream, publisher)
	return err
}
