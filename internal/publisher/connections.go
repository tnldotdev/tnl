package publisher

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const publisherConnectionCount = 2

type publisherConnectionManagerConfig struct {
	QUICConnector  muxsession.Connector
	TCPConnector   muxsession.Connector
	FallbackDelay  time.Duration
	ReconnectDelay time.Duration
	Report         func(error)
}

type publisherConnectionPhase uint8

const (
	connectionConnecting publisherConnectionPhase = iota
	connectionServing
	connectionAwaitingReplacement
)

type managedPublisherConnection struct {
	assignment controlv1.ConnectionAssignment
	cancel     context.CancelFunc
	session    *tunnel.Session
	transport  tunnel.Transport
	preferTCP  bool
	phase      publisherConnectionPhase
}

// publisherConnectionManager owns the two independently assigned publisher
// connections for one publish run. A claimed connection is not silently
// reconnected after it closes; its replacement arrives in a heartbeat.
type publisherConnectionManager struct {
	ctx              context.Context
	config           publisherConnectionManagerConfig
	route            *PublicURLServer
	publishRunID     string
	publicURLID      string
	publishRunNumber uint64

	mu           sync.Mutex
	connections  [publisherConnectionCount]*managedPublisherConnection
	changed      chan struct{}
	fallback     chan struct{}
	fallbackOnce sync.Once
	draining     bool
	closed       bool
	wg           sync.WaitGroup
}

func newPublisherConnectionManager(
	ctx context.Context,
	config publisherConnectionManagerConfig,
	route *PublicURLServer,
	publishRunID, publicURLID string,
	publishRunNumber uint64,
) (*publisherConnectionManager, error) {
	if config.QUICConnector == nil || config.TCPConnector == nil || route == nil ||
		publishRunID == "" || publicURLID == "" || publishRunNumber == 0 {
		return nil, errors.New("publisher: publisher connection manager configuration is incomplete")
	}
	if config.FallbackDelay < 0 || config.ReconnectDelay <= 0 {
		return nil, errors.New("publisher: publisher connection timing is invalid")
	}
	if config.Report == nil {
		config.Report = func(error) {}
	}
	return &publisherConnectionManager{
		ctx: ctx, config: config, route: route, publishRunID: publishRunID,
		publicURLID: publicURLID, publishRunNumber: publishRunNumber, changed: make(chan struct{}), fallback: make(chan struct{}),
	}, nil
}

func (m *publisherConnectionManager) Fallback() <-chan struct{} { return m.fallback }

func (m *publisherConnectionManager) Update(assignments []controlv1.ConnectionAssignment) error {
	bySlot, err := validateConnectionAssignments(assignments)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.draining || m.closed {
		return publisherConnectionManagerClosedError()
	}
	now := time.Now()
	for slot, assignment := range bySlot {
		current := m.connections[slot]
		if current != nil && sameConnectionAssignment(current.assignment, assignment) {
			continue
		}
		if !assignment.PublisherConnectionCredentialExpiresAt.After(now) {
			return errors.New("publisher: server returned an expired publisher connection credential")
		}
	}
	for slot, assignment := range bySlot {
		current := m.connections[slot]
		if current != nil && sameConnectionAssignment(current.assignment, assignment) {
			continue
		}
		// A relay can replace a QUIC claim before the publisher notices its
		// transport failure. Prefer TCP for the replacement in either case.
		preferTCP := current != nil && (current.preferTCP || current.phase == connectionServing && current.transport == tunnel.TransportQUIC)
		if current != nil {
			current.cancel()
		}
		connectionCtx, cancel := context.WithCancel(m.ctx)
		managed := &managedPublisherConnection{assignment: assignment, cancel: cancel, preferTCP: preferTCP}
		m.connections[slot] = managed
		m.wg.Add(1)
		go m.run(connectionCtx, slot, managed)
	}
	m.signalLocked()
	return nil
}

func (m *publisherConnectionManager) WaitReady(ctx context.Context, minimum int) error {
	if minimum < 1 || minimum > publisherConnectionCount {
		return errors.New("publisher: invalid ready publisher connection target")
	}
	for {
		m.mu.Lock()
		ready := 0
		for _, connection := range m.connections {
			if connection != nil && connection.phase == connectionServing {
				ready++
			}
		}
		changed, stopped := m.changed, m.draining || m.closed
		m.mu.Unlock()
		if stopped {
			return publisherConnectionManagerClosedError()
		}
		if ready >= minimum {
			return nil
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-changed:
		}
	}
}

func (m *publisherConnectionManager) Drain(ctx context.Context) error {
	m.mu.Lock()
	if m.draining || m.closed {
		m.mu.Unlock()
		return publisherConnectionManagerClosedError()
	}
	m.draining = true
	sessions := make([]*tunnel.Session, 0, publisherConnectionCount)
	for _, connection := range m.connections {
		if connection == nil {
			continue
		}
		if connection.phase != connectionServing {
			connection.cancel()
			continue
		}
		sessions = append(sessions, connection.session)
	}
	m.signalLocked()
	m.mu.Unlock()

	drainErrors := make([]error, len(sessions))
	var group sync.WaitGroup
	for index, session := range sessions {
		group.Add(1)
		go func() {
			defer group.Done()
			requestID, err := opaqueid.New("drain_")
			if err == nil {
				err = session.RequestPublisherDrain(ctx, requestID)
			}
			// A lost transport has already stopped admissions and closed its streams.
			if err != nil && context.Cause(ctx) == nil && errors.Is(session.Err(), muxsession.ErrClosed) {
				err = nil
			}
			drainErrors[index] = err
		}()
	}
	group.Wait()
	return errors.Join(drainErrors...)
}

func (m *publisherConnectionManager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	for _, connection := range m.connections {
		if connection != nil {
			connection.cancel()
		}
	}
	m.signalLocked()
	m.mu.Unlock()
	m.wg.Wait()
}

func (m *publisherConnectionManager) run(
	ctx context.Context,
	slot int,
	managed *managedPublisherConnection,
) {
	defer m.wg.Done()
	preferTCP := managed.preferTCP
	// failed attempts and expired credentials also wait for a new assignment.
	defer func() { m.connectionEnded(slot, managed, preferTCP) }()
	assignment := managed.assignment
	ref := tunnelv1.PublisherConnectionRef{
		PublishRunID:                 m.publishRunID,
		PublicURLID:                  m.publicURLID,
		PublishRunNumber:             m.publishRunNumber,
		PublisherConnectionID:        assignment.PublisherConnectionId,
		ConnectionSlot:               uint8(assignment.ConnectionSlot),
		ConnectionAssignmentRevision: uint64(assignment.ConnectionAssignmentRevision),
		RelayServiceID:               assignment.RelayServiceId,
	}
	hello := tunnelv1.Message{
		Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version,
		Role: tunnelv1.Publisher, Credential: assignment.PublisherConnectionCredential,
		PublisherConnection: &ref,
	}
	for time.Now().Before(assignment.PublisherConnectionCredentialExpiresAt) {
		quic := tunnel.Candidate{Connector: m.config.QUICConnector, Endpoint: muxsession.Endpoint{
			Address: assignment.RelayAddress, ServerName: assignment.TlsServerName,
		}, Transport: tunnel.TransportQUIC}
		tcp := tunnel.Candidate{Connector: m.config.TCPConnector, Endpoint: muxsession.Endpoint{
			Address: assignment.RelayAddress, ServerName: assignment.TlsServerName,
		}, Transport: tunnel.TransportTLSTCP}
		if managed.preferTCP {
			quic, tcp = tcp, quic
		}
		session, transport, err := tunnel.Race(
			ctx, quic, tcp, m.config.FallbackDelay, hello,
		)
		if err == nil {
			if !m.setSession(slot, managed, session, transport) {
				_ = session.Close()
				return
			}
			err = m.route.ServePublisherConnection(ctx, session, ref)
			preferTCP = transport == tunnel.TransportQUIC && err != nil && ctx.Err() == nil
			// stop reporting readiness before closing or logging the lost session.
			m.connectionEnded(slot, managed, preferTCP)
			_ = session.Close()
			if err != nil && ctx.Err() == nil {
				m.config.Report(fmt.Errorf("publisher: publisher connection %s closed: %w", assignment.PublisherConnectionId, err))
			}
			return
		}
		if ctx.Err() != nil {
			return
		}
		if tunnel.IsTerminalHandshakeError(err) {
			m.config.Report(fmt.Errorf("publisher: publisher connection %s rejected: %w", assignment.PublisherConnectionId, err))
			return
		}
		m.config.Report(fmt.Errorf("publisher: connect publisher connection %s: %w", assignment.PublisherConnectionId, err))
		timer := time.NewTimer(m.config.ReconnectDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (m *publisherConnectionManager) setSession(
	slot int,
	managed *managedPublisherConnection,
	session *tunnel.Session,
	transport tunnel.Transport,
) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.draining || m.closed || m.connections[slot] != managed || managed.phase != connectionConnecting {
		return false
	}
	managed.session = session
	managed.transport = transport
	if transport == tunnel.TransportTLSTCP {
		managed.preferTCP = false
		m.fallbackOnce.Do(func() { close(m.fallback) })
	}
	managed.phase = connectionServing
	m.signalLocked()
	return true
}

func (m *publisherConnectionManager) connectionEnded(slot int, managed *managedPublisherConnection, preferTCP bool) {
	m.mu.Lock()
	if !m.closed && m.connections[slot] == managed && managed.phase != connectionAwaitingReplacement {
		managed.session = nil
		managed.phase = connectionAwaitingReplacement
		managed.preferTCP = preferTCP
		m.signalLocked()
	}
	m.mu.Unlock()
}

func (m *publisherConnectionManager) signalLocked() {
	close(m.changed)
	m.changed = make(chan struct{})
}

func validateConnectionAssignments(
	assignments []controlv1.ConnectionAssignment,
) ([publisherConnectionCount]controlv1.ConnectionAssignment, error) {
	var bySlot [publisherConnectionCount]controlv1.ConnectionAssignment
	if len(assignments) != publisherConnectionCount {
		return bySlot, errors.New("publisher: server must return exactly two connection assignments")
	}
	seenConnections := make(map[string]struct{}, publisherConnectionCount)
	seenRelayServices := make(map[string]struct{}, publisherConnectionCount)
	seenSlots := [publisherConnectionCount]bool{}
	for _, assignment := range assignments {
		if assignment.ConnectionSlot < 0 || assignment.ConnectionSlot >= publisherConnectionCount || seenSlots[assignment.ConnectionSlot] ||
			assignment.PublisherConnectionId == "" || assignment.ConnectionAssignmentRevision <= 0 || assignment.RelayServiceId == "" ||
			assignment.RelayAddress == "" || assignment.TlsServerName == "" || assignment.PublisherConnectionCredential == "" ||
			assignment.PublisherConnectionCredentialExpiresAt.IsZero() || !assignment.State.Valid() {
			return bySlot, errors.New("publisher: server returned an invalid connection assignment")
		}
		if _, exists := seenConnections[assignment.PublisherConnectionId]; exists {
			return bySlot, errors.New("publisher: server returned duplicate publisher connection IDs")
		}
		if _, exists := seenRelayServices[assignment.RelayServiceId]; exists {
			return bySlot, errors.New("publisher: server returned duplicate assigned relay services")
		}
		seenConnections[assignment.PublisherConnectionId] = struct{}{}
		seenRelayServices[assignment.RelayServiceId] = struct{}{}
		seenSlots[assignment.ConnectionSlot] = true
		bySlot[assignment.ConnectionSlot] = assignment
	}
	return bySlot, nil
}

func sameConnectionAssignment(left, right controlv1.ConnectionAssignment) bool {
	return left.PublisherConnectionId == right.PublisherConnectionId &&
		left.ConnectionSlot == right.ConnectionSlot &&
		left.ConnectionAssignmentRevision == right.ConnectionAssignmentRevision &&
		left.RelayServiceId == right.RelayServiceId &&
		left.RelayAddress == right.RelayAddress &&
		left.TlsServerName == right.TlsServerName &&
		left.PublisherConnectionCredential == right.PublisherConnectionCredential &&
		left.PublisherConnectionCredentialExpiresAt.Equal(right.PublisherConnectionCredentialExpiresAt)
}

func publisherConnectionManagerClosedError() error {
	return errors.New("publisher: publisher connection manager is closed")
}
