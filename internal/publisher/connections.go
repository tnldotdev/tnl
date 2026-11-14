package publisher

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	quic "github.com/quic-go/quic-go"
	clienttelemetry "github.com/tnldotdev/tnl/internal/client/telemetry"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	telemetryv1 "github.com/tnldotdev/tnl/pkg/api/integrations/telemetry/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const publisherConnectionCount = 2

type publisherConnectionManagerConfig struct {
	Telemetry      *clienttelemetry.Scope
	QUICConnector  muxsession.Connector
	TCPConnector   muxsession.Connector
	FallbackDelay  time.Duration
	ReconnectDelay time.Duration
	Report         func(error)
}

type publisherConnectionAssignment struct {
	assignment controlv1.ConnectionAssignment
	key        string
}

// publisherConnectionManager owns both publisher connection slots and joins
// their workers on Close. after a claimed connection closes, it waits for a
// new connection assignment from a heartbeat rather than reconnecting it.
type publisherConnectionManager struct {
	config           publisherConnectionManagerConfig
	route            *PublicURLServer
	publishRunID     string
	publicURLID      string
	publishRunNumber uint64

	mu           sync.Mutex
	assignments  [publisherConnectionCount]*publisherConnectionAssignment
	sequence     uint64
	paths        *tunnel.Slots
	fallback     chan struct{}
	fallbackOnce sync.Once
	draining     bool
	closed       bool
	recovering   [2]time.Time
	recoveryPath [2]telemetryv1.Path
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
	m := &publisherConnectionManager{
		config: config, route: route, publishRunID: publishRunID,
		publicURLID: publicURLID, publishRunNumber: publishRunNumber, fallback: make(chan struct{}),
	}
	ctx = observability.WithPublisherRecoveryFrom(ctx, route.life)
	ctx = observability.WithFields(ctx, observability.Fields{Component: "publisher", ServiceProtocol: observability.ProtocolHTTP, AccessPath: "public_endpoint", Exposure: "public"})
	paths, err := tunnel.NewSlots(ctx, tunnel.SlotsConfig{
		Connect: m.connect, SingleUse: true, BackoffMin: config.ReconnectDelay, BackoffMax: config.ReconnectDelay,
		PreferTCPAfter: func(session tunnel.SlotSession, err error) bool {
			connection := session.(*publicPublisherSlot)
			return connection.transport == tunnel.TransportQUIC && err != nil && connection.ctx.Err() == nil
		}, SessionEnded: func(_ uint8, session tunnel.SlotSession, err error) {
			connection := session.(*publicPublisherSlot)
			if err != nil && connection.ctx.Err() == nil {
				m.mu.Lock()
				if !m.closed && m.recovering[connection.ref.ConnectionSlot].IsZero() {
					m.recovering[connection.ref.ConnectionSlot] = time.Now()
					m.recoveryPath[connection.ref.ConnectionSlot] = clienttelemetry.Path(connection.transport)
				}
				m.mu.Unlock()
				config.Report(fmt.Errorf("publisher: publisher connection %s closed: %w", connection.ref.PublisherConnectionID, err))
			}
		},
	})
	if err != nil {
		return nil, err
	}
	m.paths = paths
	return m, nil
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
		current := m.assignments[slot]
		if current != nil && sameConnectionAssignment(current.assignment, assignment) {
			continue
		}
		if !assignment.PublisherConnectionCredentialExpiresAt.After(now) {
			return errors.New("publisher: server returned an expired publisher connection credential")
		}
	}
	for slot, assignment := range bySlot {
		current := m.assignments[slot]
		if current != nil && sameConnectionAssignment(current.assignment, assignment) {
			continue
		}
		m.sequence++
		// lifecycle state is not an assignment change. a local counter also
		// fences changed credentials/endpoints without putting secrets in keys.
		managed := &publisherConnectionAssignment{assignment: assignment,
			key: fmt.Sprintf("%s/%d/%d", assignment.PublisherConnectionId, assignment.ConnectionAssignmentRevision, m.sequence)}
		m.assignments[slot] = managed
		if err := m.paths.Set(uint8(slot), managed.key); err != nil {
			return err
		}
	}
	return nil
}

func (m *publisherConnectionManager) WaitReady(ctx context.Context, minimum int) error {
	if minimum < 1 || minimum > publisherConnectionCount {
		return errors.New("publisher: invalid ready publisher connection target")
	}
	for {
		m.mu.Lock()
		current, changed := m.paths.Snapshot()
		ready := 0
		for _, connection := range current {
			if connection != nil {
				ready++
			}
		}
		stopped := m.draining || m.closed
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
	m.mu.Unlock()
	return m.paths.StopAdmissions(ctx)
}

func (m *publisherConnectionManager) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return m.paths.Close()
	}
	m.closed = true
	for slot, started := range m.recovering {
		if !started.IsZero() {
			m.config.Telemetry.Record(telemetryv1.Recovery, m.recoveryPath[slot], telemetryv1.Canceled, time.Since(started))
			m.recovering[slot] = time.Time{}
		}
	}
	m.mu.Unlock()
	return m.paths.Close()
}

// connect adapts the public claim handshake to the role-neutral slot worker.
// retries belong to Slots; a returned authenticated claim is always single-use.
func (m *publisherConnectionManager) connect(
	ctx context.Context,
	slot uint8,
	preferTCP bool,
) (tunnel.SlotSession, error) {
	m.mu.Lock()
	managed := m.assignments[slot]
	stopped := m.draining || m.closed || ctx.Err() != nil
	m.mu.Unlock()
	if stopped || managed == nil {
		return nil, tunnel.ErrAwaitAssignment
	}
	assignment := managed.assignment
	if !assignment.PublisherConnectionCredentialExpiresAt.After(time.Now()) {
		return nil, tunnel.ErrAwaitAssignment
	}
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
	quic := tunnel.Candidate{Connector: m.config.QUICConnector, Endpoint: muxsession.Endpoint{
		Address: assignment.RelayAddress, ServerName: assignment.TlsServerName,
	}, Transport: tunnel.TransportQUIC, Observe: m.config.Telemetry.RelayAttempt}
	tcp := tunnel.Candidate{Connector: m.config.TCPConnector, Endpoint: muxsession.Endpoint{
		Address: assignment.RelayAddress, ServerName: assignment.TlsServerName,
	}, Transport: tunnel.TransportTLSTCP, Observe: m.config.Telemetry.RelayAttempt}
	if preferTCP {
		quic, tcp = tcp, quic
	}
	connectCtx, finish := observability.PublisherOperation(ctx, "connect")
	session, transport, err := tunnel.Race(connectCtx, quic, tcp, m.config.FallbackDelay, hello)
	finish(err)
	observability.PublisherConnection(ctx, string(transport), preferTCP, err)
	if err != nil {
		if ctx.Err() == nil {
			if tunnel.IsTerminalHandshakeError(err) {
				m.config.Report(fmt.Errorf("publisher: publisher connection %s rejected: %w", assignment.PublisherConnectionId, err))
			} else {
				m.config.Report(fmt.Errorf("publisher: connect publisher connection %s: %w", assignment.PublisherConnectionId, err))
			}
		}
		return nil, err
	}
	m.mu.Lock()
	current := !m.draining && !m.closed && ctx.Err() == nil && m.assignments[slot] == managed
	if current && transport == tunnel.TransportTLSTCP {
		if !preferTCP {
			m.config.Telemetry.Record(telemetryv1.Fallback, telemetryv1.TlsTcp, telemetryv1.Succeeded, 0)
		}
		// publish fallback before Slots can expose readiness, and only while
		// the heartbeat's immutable assignment snapshot remains current.
		m.fallbackOnce.Do(func() { close(m.fallback) })
	}
	if current && !m.recovering[slot].IsZero() {
		m.config.Telemetry.Record(telemetryv1.Recovery, clienttelemetry.Path(transport), telemetryv1.Succeeded, time.Since(m.recovering[slot]))
		m.recovering[slot] = time.Time{}
	}
	m.mu.Unlock()
	if !current {
		var cleanup error
		if err := session.Close(); err != nil {
			cleanup = &tunnel.SessionCleanupError{Err: err}
		}
		return nil, errors.Join(tunnel.ErrAwaitAssignment, cleanup)
	}
	return &publicPublisherSlot{ctx: ctx, session: session, transport: transport, ref: ref, route: m.route}, nil
}

type publicPublisherSlot struct {
	ctx       context.Context
	session   *tunnel.Session
	transport tunnel.Transport
	ref       tunnelv1.PublisherConnectionRef
	route     *PublicURLServer
}

func (c *publicPublisherSlot) Serve(ctx context.Context) error {
	finish := observability.PublisherConnectionLifetime(ctx, string(c.transport), int(c.ref.ConnectionSlot))
	err := c.route.ServePublisherConnection(ctx, c.session, c.ref)
	finish(err, ctx.Err() != nil || err == nil)
	return err
}

func (c *publicPublisherSlot) Transport() tunnel.Transport { return c.transport }
func (c *publicPublisherSlot) Close() error                { return c.session.Close() }

func (c *publicPublisherSlot) Drain(ctx context.Context) error {
	requestID, err := opaqueid.New(opaqueid.DrainPrefix)
	if err == nil {
		err = c.session.RequestPublisherDrain(ctx, requestID)
	}
	// a closed transport has no admissions or visitor streams left to drain.
	// TCP closure can surface as a reset when the relay closes with unread data,
	// but it must be confirmed by the session, not inferred from a stream reset.
	closed := false
	select {
	case <-c.session.Done():
		closed = true
	default:
	}
	if err != nil && context.Cause(ctx) == nil && publisherDrainClosure(err, closed) {
		return nil
	}
	return err
}

// every joined cause must be closure-related. a simultaneous protocol, timeout,
// or cleanup failure remains an error even after the transport has disappeared.
func publisherDrainClosure(err error, closed bool) bool {
	if failure, ok := err.(net.Error); ok && failure.Timeout() {
		return false
	}
	switch err {
	case muxsession.ErrClosed, net.ErrClosed:
		return true
	case io.EOF, io.ErrClosedPipe, syscall.ECONNRESET, syscall.EPIPE:
		return closed
	}
	switch err := err.(type) {
	case *quic.ApplicationError:
		return err.ErrorCode == 0
	case interface{ Unwrap() []error }:
		causes := err.Unwrap()
		if len(causes) == 0 {
			return false
		}
		for _, cause := range causes {
			if !publisherDrainClosure(cause, closed) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return publisherDrainClosure(err.Unwrap(), closed)
	}
	return false
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
