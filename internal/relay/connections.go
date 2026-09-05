package relay

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var ErrDraining = errors.New("relay: draining")

// PublisherConnection is one locally connected publisher assignment.
type PublisherConnection struct {
	ref     tunnelv1.PublisherConnectionRef
	claimed relayv1.ClaimedPublisherConnection
	session *tunnel.Session

	mu       sync.Mutex
	draining bool
	closed   bool
	opening  int
	streams  map[*trackedConn]struct{}
	changed  chan struct{}

	closeOnce sync.Once
	closeErr  error
}

func NewPublisherConnection(
	ref tunnelv1.PublisherConnectionRef,
	claimed relayv1.ClaimedPublisherConnection,
	session *tunnel.Session,
) (*PublisherConnection, error) {
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	if session == nil {
		return nil, errors.New("relay: tunnel session is required")
	}
	if claimed.PublisherConnectionId != ref.PublisherConnectionID ||
		claimed.RouteSessionId != ref.RouteSessionID || claimed.RouteId != ref.RouteID ||
		claimed.RouteVersion != int64(ref.RouteVersion) || claimed.ConnectionSlot != int(ref.ConnectionSlot) ||
		claimed.ConnectionAssignmentRevision != int64(ref.ConnectionAssignmentRevision) ||
		claimed.RelayServiceId != ref.RelayServiceID {
		return nil, errors.New("relay: claimed publisher connection does not match its reference")
	}
	return &PublisherConnection{
		ref: ref, claimed: claimed, session: session,
		streams: make(map[*trackedConn]struct{}), changed: make(chan struct{}),
	}, nil
}

func (c *PublisherConnection) Ref() tunnelv1.PublisherConnectionRef { return c.ref }

func (c *PublisherConnection) OpenVisitor(ctx context.Context, visitorConnectionID string) (net.Conn, error) {
	if err := c.beginOpen(); err != nil {
		return nil, err
	}
	stream, err := c.session.OpenVisitorStream(ctx, tunnelv1.VisitorStreamHeader{
		ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.VisitorStream,
		VisitorConnectionID: visitorConnectionID, RouteID: c.ref.RouteID,
		RouteSessionID: c.ref.RouteSessionID, RouteVersion: c.ref.RouteVersion,
		PublisherConnectionID:        c.ref.PublisherConnectionID,
		ConnectionAssignmentRevision: c.ref.ConnectionAssignmentRevision,
	})
	return c.finishOpen(stream, err)
}

func (c *PublisherConnection) beginOpen() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.stateErrorLocked(); err != nil {
		return err
	}
	c.opening++
	return nil
}

func (c *PublisherConnection) finishOpen(connection net.Conn, openErr error) (net.Conn, error) {
	c.mu.Lock()
	c.opening--
	stateErr := c.stateErrorLocked()
	if openErr == nil && stateErr == nil {
		tracked := &trackedConn{Conn: connection}
		tracked.release = func() {
			c.mu.Lock()
			delete(c.streams, tracked)
			c.notifyLocked()
			c.mu.Unlock()
		}
		c.streams[tracked] = struct{}{}
		c.notifyLocked()
		c.mu.Unlock()
		return tracked, nil
	}
	c.notifyLocked()
	c.mu.Unlock()
	if connection != nil {
		_ = connection.Close()
	}
	if openErr != nil {
		return nil, openErr
	}
	return nil, stateErr
}

func (c *PublisherConnection) Drain(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	c.draining = true
	for c.opening != 0 || len(c.streams) != 0 {
		changed := c.changed
		c.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			_ = c.Close()
			return context.Cause(ctx)
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return net.ErrClosed
		}
	}
	c.mu.Unlock()
	return nil
}

func (c *PublisherConnection) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.draining = true
		streams := c.snapshotLocked()
		c.notifyLocked()
		c.mu.Unlock()
		for _, stream := range streams {
			_ = stream.Close()
		}
		c.closeErr = c.session.Close()
		c.mu.Lock()
		for c.opening != 0 || len(c.streams) != 0 {
			changed := c.changed
			c.mu.Unlock()
			<-changed
			c.mu.Lock()
		}
		c.mu.Unlock()
	})
	return c.closeErr
}

func (c *PublisherConnection) stateErrorLocked() error {
	if c.closed {
		return net.ErrClosed
	}
	if c.draining {
		return ErrDraining
	}
	return nil
}

func (c *PublisherConnection) snapshotLocked() []*trackedConn {
	result := make([]*trackedConn, 0, len(c.streams))
	for stream := range c.streams {
		result = append(result, stream)
	}
	return result
}

func (c *PublisherConnection) notifyLocked() {
	close(c.changed)
	c.changed = make(chan struct{})
}

type trackedConn struct {
	net.Conn
	closeOnce sync.Once
	closeErr  error
	release   func()
}

func (c *trackedConn) Close() error {
	c.closeOnce.Do(func() {
		defer c.release()
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

func (c *trackedConn) CloseRead() error {
	connection, ok := c.Conn.(interface{ CloseRead() error })
	if !ok {
		return errors.ErrUnsupported
	}
	return connection.CloseRead()
}

func (c *trackedConn) CloseWrite() error {
	connection, ok := c.Conn.(interface{ CloseWrite() error })
	if !ok {
		return errors.ErrUnsupported
	}
	return connection.CloseWrite()
}

type slotKey struct {
	routeSessionID string
	slot           uint8
}

// Registry is a concurrency-safe registry of publisher connections held by one relay process.
type Registry struct {
	observer    OperationObserver
	mu          sync.Mutex
	connections map[string]*PublisherConnection
	slots       map[slotKey]*PublisherConnection
	draining    bool
	closed      bool
	closeDone   chan struct{}
	closeErr    error
}

func NewRegistry() *Registry { return new(Registry) }

// Instrument configures observation before the registry begins serving work.
func (r *Registry) Instrument(observer OperationObserver) { r.observer = observer }

func (r *Registry) Insert(connection *PublisherConnection) error {
	if connection == nil {
		return errors.New("relay: publisher connection is required")
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return net.ErrClosed
	}
	if r.draining {
		r.mu.Unlock()
		return ErrDraining
	}
	if r.connections == nil {
		r.connections = make(map[string]*PublisherConnection)
		r.slots = make(map[slotKey]*PublisherConnection)
	}
	ref := connection.ref
	if _, exists := r.connections[ref.PublisherConnectionID]; exists {
		r.mu.Unlock()
		return &tunnel.ProtocolError{Code: tunnelv1.DuplicatePublisherConnection}
	}
	key := slotKey{routeSessionID: ref.RouteSessionID, slot: ref.ConnectionSlot}
	previous := r.slots[key]
	if previous != nil && previous.ref.ConnectionAssignmentRevision >= ref.ConnectionAssignmentRevision {
		r.mu.Unlock()
		return &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
	}
	if previous != nil {
		delete(r.connections, previous.ref.PublisherConnectionID)
	}
	r.connections[ref.PublisherConnectionID] = connection
	r.slots[key] = connection
	r.mu.Unlock()
	if previous != nil {
		_ = previous.Close()
	}
	return nil
}

func (r *Registry) Candidate(
	header tunnelv1.InternalForwardingHeader,
	now time.Time,
) (*PublisherConnection, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	connection := r.connections[header.PublisherConnectionID]
	if r.closed || r.draining || connection == nil || !header.RouteExpiresAt.After(now) || !header.LeaseExpiresAt.After(now) {
		return nil, false
	}
	ref, claimed := connection.ref, connection.claimed
	if header.RouteID != ref.RouteID || header.RouteSessionID != ref.RouteSessionID ||
		header.RouteVersion != ref.RouteVersion || header.ConnectionSlot != ref.ConnectionSlot ||
		header.ConnectionAssignmentRevision != ref.ConnectionAssignmentRevision ||
		header.RelayServiceID != ref.RelayServiceID || header.RelayID != claimed.RelayId ||
		header.RelayRunID != claimed.RelayRunId || header.RelayLeaseRevision != uint64(claimed.RelayLeaseRevision) {
		return nil, false
	}
	return connection, true
}

func (r *Registry) Remove(connection *PublisherConnection) bool {
	if connection == nil {
		return false
	}
	r.mu.Lock()
	current := r.connections[connection.ref.PublisherConnectionID]
	if current != connection {
		r.mu.Unlock()
		return false
	}
	delete(r.connections, connection.ref.PublisherConnectionID)
	key := slotKey{routeSessionID: connection.ref.RouteSessionID, slot: connection.ref.ConnectionSlot}
	if r.slots[key] == connection {
		delete(r.slots, key)
	}
	r.mu.Unlock()
	_ = connection.Close()
	return true
}

func (r *Registry) Load() (connections, streams int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return 0, 0
	}
	connections = int64(len(r.connections))
	for _, connection := range r.connections {
		connection.mu.Lock()
		streams += int64(connection.opening + len(connection.streams))
		connection.mu.Unlock()
	}
	return connections, streams
}

func (r *Registry) Drain(ctx context.Context) (retErr error) {
	finish := startOperation(ctx, r.observer, "RelayDrain")
	defer func() { finish(retErr) }()
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return net.ErrClosed
	}
	r.draining = true
	connections := r.snapshotLocked()
	r.mu.Unlock()
	errorsFound := make(chan error, len(connections))
	var group sync.WaitGroup
	for _, connection := range connections {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := connection.Drain(ctx); err != nil {
				errorsFound <- err
			}
		}()
	}
	group.Wait()
	close(errorsFound)
	var result error
	for err := range errorsFound {
		if !errors.Is(err, net.ErrClosed) {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (r *Registry) Close() error {
	r.mu.Lock()
	if r.closed {
		done := r.closeDone
		r.mu.Unlock()
		<-done
		return r.closeErr
	}
	r.closed = true
	r.draining = true
	r.closeDone = make(chan struct{})
	done := r.closeDone
	connections := r.snapshotLocked()
	clear(r.connections)
	clear(r.slots)
	r.mu.Unlock()
	var result error
	for _, connection := range connections {
		result = errors.Join(result, connection.Close())
	}
	r.mu.Lock()
	r.closeErr = result
	close(done)
	r.mu.Unlock()
	return result
}

func (r *Registry) snapshotLocked() []*PublisherConnection {
	result := make([]*PublisherConnection, 0, len(r.connections))
	for _, connection := range r.connections {
		result = append(result, connection)
	}
	return result
}
