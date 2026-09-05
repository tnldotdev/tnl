package publisher

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
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

type managedPublisherConnection struct {
	plan   controlv1.PublisherConnectionPlan
	cancel context.CancelFunc
	ready  bool
}

// publisherConnectionManager owns the two independently assigned publisher
// connections for one route session. A claimed connection is not silently
// reconnected after it closes; its replacement arrives in a heartbeat.
type publisherConnectionManager struct {
	ctx            context.Context
	config         publisherConnectionManagerConfig
	route          *Route
	routeSessionID string
	routeID        string
	routeVersion   uint64

	mu          sync.Mutex
	connections [publisherConnectionCount]*managedPublisherConnection
	changed     chan struct{}
	closed      bool
	wg          sync.WaitGroup
}

func newPublisherConnectionManager(
	ctx context.Context,
	config publisherConnectionManagerConfig,
	route *Route,
	routeSessionID, routeID string,
	routeVersion uint64,
) (*publisherConnectionManager, error) {
	if config.QUICConnector == nil || config.TCPConnector == nil || route == nil ||
		routeSessionID == "" || routeID == "" || routeVersion == 0 {
		return nil, errors.New("publisher: publisher connection manager configuration is incomplete")
	}
	if config.FallbackDelay < 0 || config.ReconnectDelay <= 0 {
		return nil, errors.New("publisher: publisher connection timing is invalid")
	}
	if config.Report == nil {
		config.Report = func(error) {}
	}
	return &publisherConnectionManager{
		ctx: ctx, config: config, route: route, routeSessionID: routeSessionID,
		routeID: routeID, routeVersion: routeVersion, changed: make(chan struct{}),
	}, nil
}

func (m *publisherConnectionManager) Update(plans []controlv1.PublisherConnectionPlan) error {
	bySlot, err := validatePublisherConnectionPlans(plans)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return publisherConnectionManagerClosedError()
	}
	now := time.Now()
	for slot, plan := range bySlot {
		current := m.connections[slot]
		if current != nil && samePublisherConnectionPlan(current.plan, plan) {
			continue
		}
		if !plan.PublisherConnectionCredentialExpiresAt.After(now) {
			return errors.New("publisher: server returned an expired publisher connection credential")
		}
	}
	for slot, plan := range bySlot {
		current := m.connections[slot]
		if current != nil && samePublisherConnectionPlan(current.plan, plan) {
			continue
		}
		if current != nil {
			current.cancel()
		}
		connectionCtx, cancel := context.WithCancel(m.ctx)
		managed := &managedPublisherConnection{plan: plan, cancel: cancel}
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
			if connection != nil && connection.ready {
				ready++
			}
		}
		changed, closed := m.changed, m.closed
		m.mu.Unlock()
		if ready >= minimum {
			return nil
		}
		if closed {
			return publisherConnectionManagerClosedError()
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-changed:
		}
	}
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
	plan := managed.plan
	ref := tunnelv1.PublisherConnectionRef{
		RouteSessionID:               m.routeSessionID,
		RouteID:                      m.routeID,
		RouteVersion:                 m.routeVersion,
		PublisherConnectionID:        plan.PublisherConnectionId,
		ConnectionSlot:               uint8(plan.ConnectionSlot),
		ConnectionAssignmentRevision: uint64(plan.ConnectionAssignmentRevision),
		RelayServiceID:               plan.RelayServiceId,
	}
	hello := tunnelv1.Message{
		Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version,
		Role: tunnelv1.Publisher, Credential: plan.PublisherConnectionCredential,
		PublisherConnection: &ref,
	}
	for time.Now().Before(plan.PublisherConnectionCredentialExpiresAt) {
		session, err := tunnel.Race(
			ctx,
			tunnel.Candidate{Connector: m.config.QUICConnector, Endpoint: muxsession.Endpoint{
				Address: plan.RelayAddress, ServerName: plan.TlsServerName,
			}},
			tunnel.Candidate{Connector: m.config.TCPConnector, Endpoint: muxsession.Endpoint{
				Address: plan.RelayAddress, ServerName: plan.TlsServerName,
			}},
			m.config.FallbackDelay,
			hello,
		)
		if err == nil {
			m.setReady(slot, managed, true)
			err = m.route.ServePublisherConnection(ctx, session, ref)
			m.setReady(slot, managed, false)
			_ = session.Close()
			if err != nil && ctx.Err() == nil {
				m.config.Report(fmt.Errorf("publisher: publisher connection %s closed: %w", plan.PublisherConnectionId, err))
			}
			return
		}
		if ctx.Err() != nil {
			return
		}
		var protocolError *tunnel.ProtocolError
		if errors.As(err, &protocolError) && protocolError.Code != tunnelv1.Unavailable &&
			protocolError.Code != tunnelv1.CapacityExceeded && protocolError.Code != tunnelv1.Internal {
			m.config.Report(fmt.Errorf("publisher: publisher connection %s rejected: %w", plan.PublisherConnectionId, err))
			return
		}
		m.config.Report(fmt.Errorf("publisher: connect publisher connection %s: %w", plan.PublisherConnectionId, err))
		timer := time.NewTimer(m.config.ReconnectDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (m *publisherConnectionManager) setReady(
	slot int,
	managed *managedPublisherConnection,
	ready bool,
) {
	m.mu.Lock()
	if m.connections[slot] == managed && managed.ready != ready {
		managed.ready = ready
		m.signalLocked()
	}
	m.mu.Unlock()
}

func (m *publisherConnectionManager) signalLocked() {
	close(m.changed)
	m.changed = make(chan struct{})
}

func validatePublisherConnectionPlans(
	plans []controlv1.PublisherConnectionPlan,
) ([publisherConnectionCount]controlv1.PublisherConnectionPlan, error) {
	var bySlot [publisherConnectionCount]controlv1.PublisherConnectionPlan
	if len(plans) != publisherConnectionCount {
		return bySlot, errors.New("publisher: server must return exactly two publisher connection plans")
	}
	seenConnections := make(map[string]struct{}, publisherConnectionCount)
	seenRelayServices := make(map[string]struct{}, publisherConnectionCount)
	seenSlots := [publisherConnectionCount]bool{}
	for _, plan := range plans {
		if plan.ConnectionSlot < 0 || plan.ConnectionSlot >= publisherConnectionCount || seenSlots[plan.ConnectionSlot] ||
			plan.PublisherConnectionId == "" || plan.ConnectionAssignmentRevision <= 0 || plan.RelayServiceId == "" ||
			plan.RelayAddress == "" || plan.TlsServerName == "" || plan.PublisherConnectionCredential == "" ||
			plan.PublisherConnectionCredentialExpiresAt.IsZero() || !plan.State.Valid() {
			return bySlot, errors.New("publisher: server returned an invalid publisher connection plan")
		}
		if _, exists := seenConnections[plan.PublisherConnectionId]; exists {
			return bySlot, errors.New("publisher: server returned duplicate publisher connection IDs")
		}
		if _, exists := seenRelayServices[plan.RelayServiceId]; exists {
			return bySlot, errors.New("publisher: server returned duplicate assigned relay services")
		}
		seenConnections[plan.PublisherConnectionId] = struct{}{}
		seenRelayServices[plan.RelayServiceId] = struct{}{}
		seenSlots[plan.ConnectionSlot] = true
		bySlot[plan.ConnectionSlot] = plan
	}
	return bySlot, nil
}

func samePublisherConnectionPlan(left, right controlv1.PublisherConnectionPlan) bool {
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
