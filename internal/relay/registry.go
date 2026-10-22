package relay

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type slotKey struct {
	publishRunID string
	slot         uint8
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
	key := slotKey{publishRunID: ref.PublishRunID, slot: ref.ConnectionSlot}
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
	if previous == nil {
		if observer, ok := r.observer.(interface{ AddRegisteredPublisherConnections(int) }); ok {
			observer.AddRegisteredPublisherConnections(1)
		}
	}
	r.mu.Unlock()
	if previous != nil {
		_ = previous.Close()
	}
	return nil
}

func (r *Registry) Candidate(
	header tunnelv1.InternalForwardingHeader,
	lease relayv1.RelayLease,
	now time.Time,
) (*PublisherConnection, bool) {
	return r.candidate(header, lease, now, true)
}

func (r *Registry) candidate(header tunnelv1.InternalForwardingHeader, lease relayv1.RelayLease, now time.Time, opening bool) (*PublisherConnection, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	connection := r.connections[header.PublisherConnectionID]
	// ingress copied the deadline when control published this public URL.
	// relay renewals do not republish it; check this process's current lease
	// so an expired or replaced relay cannot accept a visitor stream.
	if r.closed || r.draining || connection == nil || opening && !header.PublicUrlExpiresAt.After(now) ||
		lease.RelayLeaseRevision <= 0 || !lease.LeaseExpiresAt.After(now) || lease.Draining ||
		lease.RelayServiceId != header.RelayServiceID || lease.RelayId != header.RelayID ||
		lease.RelayRunId != header.RelayRunID || uint64(lease.RelayLeaseRevision) != header.RelayLeaseRevision {
		return nil, false
	}
	ref, claimed := connection.ref, connection.claimed
	if tunnel.PublicForwardingRef(header) != ref || header.RelayID != claimed.RelayId ||
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
	if observer, ok := r.observer.(interface{ AddRegisteredPublisherConnections(int) }); ok {
		observer.AddRegisteredPublisherConnections(-1)
	}
	key := slotKey{publishRunID: connection.ref.PublishRunID, slot: connection.ref.ConnectionSlot}
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
	if observer, ok := r.observer.(interface{ AddRegisteredPublisherConnections(int) }); ok {
		observer.AddRegisteredPublisherConnections(-len(connections))
	}
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
