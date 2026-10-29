package ingress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	ingressbackend "github.com/tnldotdev/tnl/internal/ingress/backend"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const relaySessionSetupTimeout = 10 * time.Second

type VisitorSourceSigner func(ingressv1.IngressRoutingTableEntry, string, netip.AddrPort, netip.AddrPort) (string, error)

type ForwarderConfig struct {
	SignVisitorSource VisitorSourceSigner
	Context           context.Context
	TLSConfig         *tls.Config
	ClusterSecret     string
	TransportConfig   muxsession.TLSYamuxConfig
	Observer          OperationObserver
	OnSessionClosed   func(relayServiceID, relayID, origin string, cause error)
	PromoteVisitor    func(context.Context, tunnelv1.AdmissionHeader) tunnelv1.AdmissionResult
}

// Forwarder pools authenticated sessions to exact relay processes and opens
// acknowledged internal-forwarding streams for visitor connections.
type Forwarder struct {
	signVisitorSource VisitorSourceSigner
	connector         relayConnector
	observer          OperationObserver
	context           context.Context
	cancel            context.CancelFunc
	onSessionClosed   func(relayServiceID, relayID, origin string, cause error)

	mu        sync.Mutex
	sessions  map[relaySessionKey]*relaySession
	closed    bool
	closeDone chan struct{}
	closeErr  error
	pending   map[string]*forwardingAdmission
	promote   func(context.Context, tunnelv1.AdmissionHeader) tunnelv1.AdmissionResult
}

func NewForwarder(config ForwarderConfig) (*Forwarder, error) {
	if config.SignVisitorSource == nil {
		return nil, visitortoken.ErrVisitorSource
	}
	connector, err := newTLSRelayConnector(config.TLSConfig, config.ClusterSecret, config.TransportConfig)
	if err != nil {
		return nil, err
	}
	f := newForwarderContext(config.Context, connector)
	f.signVisitorSource = config.SignVisitorSource
	f.observer = config.Observer
	f.onSessionClosed = config.OnSessionClosed
	f.promote = config.PromoteVisitor
	return f, nil
}

func newForwarder(connector relayConnector) *Forwarder {
	return newForwarderContext(context.Background(), connector)
}

func newForwarderContext(owner context.Context, connector relayConnector) *Forwarder {
	if owner == nil {
		owner = context.Background()
	}
	ctx, cancel := context.WithCancel(owner)
	return &Forwarder{connector: connector, context: ctx, cancel: cancel, sessions: make(map[relaySessionKey]*relaySession), pending: make(map[string]*forwardingAdmission)}
}

// Backends preserves control's publisher-connection order. every returned
// backend is bound to the publish run number, assignment, and concrete relay lease
// represented by entry.
func (f *Forwarder) Backends(entry ingressv1.IngressRoutingTableEntry) ([]ingressbackend.Backend, error) {
	if f == nil || f.connector == nil {
		return nil, errors.New("ingress: forwarding connector is required")
	}
	if entry.PublishRunNumber <= 0 {
		return nil, errors.New("ingress: forwarding publish run number is invalid")
	}
	backends := make([]ingressbackend.Backend, 0, len(entry.PublisherConnections))
	for _, connection := range entry.PublisherConnections {
		if connection.ConnectionSlot < 0 || connection.ConnectionSlot > 1 ||
			connection.ConnectionAssignmentRevision <= 0 || connection.RelayLeaseRevision <= 0 ||
			connection.InternalRelayAddress == "" || connection.TlsServerName == "" {
			return nil, errors.New("ingress: forwarding publisher connection is invalid")
		}
		target := relayTarget{
			address: connection.InternalRelayAddress, serverName: connection.TlsServerName,
			relayServiceID: connection.RelayServiceId, relayID: connection.RelayId,
			relayRunID: connection.RelayRunId, relayLeaseRevision: uint64(connection.RelayLeaseRevision),
		}
		header := tunnelv1.InternalForwardingHeader{
			ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.InternalForwardingStream,
			VisitorConnectionID: "visitor", PublicURLID: entry.PublicUrlId, PublishRunID: entry.PublishRunId,
			PublishRunNumber: uint64(entry.PublishRunNumber), PublisherConnectionID: connection.PublisherConnectionId,
			ConnectionSlot:               uint8(connection.ConnectionSlot),
			ConnectionAssignmentRevision: uint64(connection.ConnectionAssignmentRevision),
			RelayServiceID:               connection.RelayServiceId, RelayID: connection.RelayId,
			RelayRunID: connection.RelayRunId, RelayLeaseRevision: uint64(connection.RelayLeaseRevision),
			PublicUrlExpiresAt: entry.PublicUrlExpiresAt, LeaseExpiresAt: connection.LeaseExpiresAt,
		}
		if err := header.Validate(); err != nil {
			return nil, fmt.Errorf("ingress: forwarding publisher connection is invalid: %w", err)
		}
		header.VisitorConnectionID = ""
		backends = append(backends, forwardingBackend{forwarder: f, target: target, header: header})
	}
	return backends, nil
}

// PublicURL converts one validated routing-table projection into an immutable
// public URL view used by Server for a visitor connection.
func (f *Forwarder) PublicURL(entry ingressv1.IngressRoutingTableEntry) (PublicURL, error) {
	all, err := f.Backends(entry)
	if err != nil {
		return PublicURL{}, err
	}
	backends := make([]ingressbackend.Backend, 0, len(all))
	assignments := make([]tunnelv1.AdmissionHeader, 0, len(all))
	for index, backend := range all {
		assignments = append(assignments, backend.(forwardingBackend).header.Admission())
		connection := entry.PublisherConnections[index]
		if connection.AvailableStreams == nil || *connection.AvailableStreams > 0 {
			backends = append(backends, backend)
		}
	}
	var hashed *ippolicy.Policy
	if entry.IpPolicy == ingressv1.HashedAllowlist {
		if entry.IpPolicyKey == nil || len(*entry.IpPolicyKey) != 32 || len(entry.AllowedIpHashes) == 0 {
			return PublicURL{}, errors.New("ingress: routing-table hashed IP policy is incomplete")
		}
		var key [32]byte
		copy(key[:], *entry.IpPolicyKey)
		entries := make([]ippolicy.Entry, 0, len(entry.AllowedIpHashes))
		for _, item := range entry.AllowedIpHashes {
			entries = append(entries, ippolicy.Entry{
				Family: string(item.Family), Bits: item.PrefixLength, Digest: item.Digest,
			})
		}
		policy, err := ippolicy.New(key, entries)
		if err != nil {
			return PublicURL{}, fmt.Errorf("ingress: routing-table hashed IP policy: %w", err)
		}
		hashed = &policy
	} else if entry.IpPolicy != ingressv1.AllowAll || len(entry.AllowedIpHashes) != 0 || entry.IpPolicyKey != nil {
		return PublicURL{}, errors.New("ingress: routing-table IP policy is inconsistent")
	}
	route := PublicURL{
		AttestSource: func(visitorID string, source, destination netip.AddrPort) (string, error) {
			if f.signVisitorSource == nil {
				return "", visitortoken.ErrVisitorSource
			}
			return f.signVisitorSource(entry, visitorID, source, destination)
		},
		ID: entry.PublicUrlId, PublishRunNumber: uint64(entry.PublishRunNumber),
		PublishRunID:   entry.PublishRunId,
		HashedIPPolicy: hashed, AllowAll: entry.IpPolicy == ingressv1.AllowAll, Backends: backends,
		assignments: assignments,
	}
	if entry.ServiceProtocol != nil {
		route.ServiceProtocol = string(*entry.ServiceProtocol)
	} else {
		route.ServiceProtocol = "http"
	}
	route.AccessMode = string(entry.AccessMode)
	if entry.Traffic != nil {
		limits, err := routingTraffic(*entry.Traffic)
		if err != nil {
			return PublicURL{}, err
		}
		route.Traffic = &limits
	}
	if entry.RecoveryEpisodeId != nil && *entry.RecoveryEpisodeId > 0 {
		route.RecoveryEpisodeID = uint64(*entry.RecoveryEpisodeId)
	}
	return route, nil
}

func (f *Forwarder) PublicURLs(entries []ingressv1.IngressRoutingTableEntry) ([]PublicURL, error) {
	result := make([]PublicURL, 0, len(entries))
	for _, entry := range entries {
		route, err := f.PublicURL(entry)
		if err != nil {
			return nil, err
		}
		result = append(result, route)
	}
	return result, nil
}

// Close stops new forwarding work and closes every pooled relay session.
func (f *Forwarder) Close() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	if f.closed {
		done := f.closeDone
		f.mu.Unlock()
		<-done
		return f.closeErr
	}
	f.closed = true
	f.cancel()
	f.closeDone = make(chan struct{})
	done := f.closeDone
	entries := make([]*relaySession, 0, len(f.sessions))
	for _, entry := range f.sessions {
		entries = append(entries, entry)
	}
	clear(f.sessions)
	f.mu.Unlock()
	result := closeRelaySessions(entries)
	f.mu.Lock()
	f.closeErr = result
	close(done)
	f.mu.Unlock()
	return result
}

type forwardingBackend struct {
	forwarder *Forwarder
	target    relayTarget
	header    tunnelv1.InternalForwardingHeader
}

// Open waits for the relay to accept an internal forwarding stream. the caller
// owns the stream, not the pooled session; acceptance does not establish visitor
// TLS or prove that the local service is healthy.
func (b forwardingBackend) Open(ctx context.Context, visitorConnectionID string) (net.Conn, error) {
	return b.open(ctx, visitorConnectionID, false)
}

func (b forwardingBackend) OpenPending(ctx context.Context, visitorConnectionID string) (net.Conn, error) {
	return b.open(ctx, visitorConnectionID, true)
}

func (b forwardingBackend) open(ctx context.Context, visitorConnectionID string, denied bool) (result net.Conn, retErr error) {
	ctx, finish := observability.Start(ctx, "ingress.relay_attempt")
	defer func() { finish(retErr) }()
	header := b.header
	header.VisitorConnectionID = visitorConnectionID
	header.AccessPending = denied
	if err := header.Validate(); err != nil {
		return nil, fmt.Errorf("ingress: internal forwarding header: %w", err)
	}
	for attempt := 0; ; attempt++ {
		session, reused, err := b.forwarder.session(ctx, b.target)
		if err != nil {
			return nil, err
		}
		started := time.Now()
		var binding *forwardingAdmission
		if denied {
			binding = &forwardingAdmission{session: session, header: header.Admission()}
			b.forwarder.mu.Lock()
			if b.forwarder.pending[visitorConnectionID] != nil {
				b.forwarder.mu.Unlock()
				return nil, errors.New("ingress: duplicate pending visitor")
			}
			b.forwarder.pending[visitorConnectionID] = binding
			b.forwarder.mu.Unlock()
		}
		stream, err := session.OpenInternalForwardingStream(ctx, header)
		b.forwarder.observe("IngressForwardingAck", err, started)
		if err == nil {
			if binding != nil {
				return &pendingForwardingConn{Conn: stream, remove: func() { b.forwarder.removeAdmission(visitorConnectionID, binding) }}, nil
			}
			return stream, nil
		}
		if binding != nil {
			b.forwarder.removeAdmission(visitorConnectionID, binding)
		}
		var protocolError *tunnel.ProtocolError
		if errors.As(err, &protocolError) || ctx.Err() != nil && session.Err() == nil {
			return nil, err
		}
		// a failed stream does not invalidate a still-usable pooled session.
		// closing it would also drop unrelated visitor streams; ingress can try
		// another connected relay for this visitor before sending visitor bytes.
		if session.Err() == nil && b.forwarder.currentSession(b.target.key(), session) {
			return nil, fmt.Errorf("ingress: open internal forwarding stream: %w", err)
		}
		err = errors.Join(err, b.forwarder.invalidate(b.target.key(), session))
		// another visitor may populate the pool before our retry. at most one
		// retry is allowed, even if it reuses a session.
		if !reused || attempt == 1 || ctx.Err() != nil {
			return nil, fmt.Errorf("ingress: open internal forwarding stream: %w", err)
		}
	}
}

func (b forwardingBackend) connectionSlot() string {
	if b.header.ConnectionSlot == 0 {
		return "0"
	}
	return "1"
}

type relayTarget struct {
	address            string
	serverName         string
	relayServiceID     string
	relayID            string
	relayRunID         string
	relayLeaseRevision uint64
}

func (t relayTarget) key() relaySessionKey {
	return relaySessionKey(t)
}

type relaySessionKey relayTarget

type relaySession struct {
	ready   chan struct{}
	cancel  context.CancelFunc
	session *tunnel.Session
	err     error
}

func (f *Forwarder) session(ctx context.Context, target relayTarget) (*tunnel.Session, bool, error) {
	key := target.key()
	for {
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			return nil, false, net.ErrClosed
		}
		entry := f.sessions[key]
		created := false
		if entry == nil {
			obsolete, err := f.removeSupersededLocked(key)
			if err != nil {
				f.mu.Unlock()
				return nil, false, err
			}
			connectCtx, cancel := context.WithTimeout(f.context, relaySessionSetupTimeout)
			entry = &relaySession{ready: make(chan struct{}), cancel: cancel}
			f.sessions[key] = entry
			created = true
			f.mu.Unlock()
			_ = closeRelaySessions(obsolete)
			go f.connect(connectCtx, key, target, entry)
		} else {
			f.mu.Unlock()
		}
		select {
		case <-entry.ready:
		case <-ctx.Done():
			return nil, false, context.Cause(ctx)
		}
		if entry.err != nil {
			return nil, false, fmt.Errorf("ingress: connect to relay process: %w", entry.err)
		}
		select {
		case <-entry.session.Done():
			f.invalidate(key, entry.session)
			continue
		default:
			return entry.session, !created, nil
		}
	}
}

func (f *Forwarder) connect(ctx context.Context, key relaySessionKey, target relayTarget, entry *relaySession) {
	ctx, finish := observability.Start(ctx, "ingress.relay_connect")
	started := time.Now()
	transport, err := f.connector.Connect(ctx, target)
	var session *tunnel.Session
	if err == nil {
		session, err = tunnel.Dial(ctx, transport, tunnelv1.Message{
			Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Ingress,
			Credential: f.connector.Credential(),
		})
	}
	entry.cancel()
	finish(err)
	f.observe("IngressRelayConnect", err, started)

	f.mu.Lock()
	current := !f.closed && f.sessions[key] == entry
	if current && err == nil {
		entry.session = session
	} else {
		if current {
			delete(f.sessions, key)
		}
		if err == nil {
			err = net.ErrClosed
		}
		entry.err = err
	}
	close(entry.ready)
	f.mu.Unlock()

	if err != nil {
		if session != nil {
			_ = session.Close()
		}
		return
	}
	go f.removeWhenDone(key, entry, session)
	go func() {
		_ = session.ServeAdmissions(f.context, tunnelv1.IngressAdmissionStream, func(ctx context.Context, h tunnelv1.AdmissionHeader) tunnelv1.AdmissionResult {
			return f.promoteAdmission(ctx, session, h)
		})
	}()
}

func (f *Forwarder) currentSession(key relaySessionKey, session *tunnel.Session) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	entry := f.sessions[key]
	return entry != nil && entry.session == session
}

func (f *Forwarder) removeSupersededLocked(current relaySessionKey) ([]*relaySession, error) {
	var keys []relaySessionKey
	for key := range f.sessions {
		if key != current && key.relayServiceID == current.relayServiceID && key.relayID == current.relayID {
			// public URLs receive relay replacements independently. an older
			// projection must not evict a newer session or its live visitors,
			// including while that replacement is still connecting.
			if key.relayLeaseRevision >= current.relayLeaseRevision {
				return nil, &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
			}
			keys = append(keys, key)
		}
	}
	var obsolete []*relaySession
	for _, key := range keys {
		obsolete = append(obsolete, f.sessions[key])
		delete(f.sessions, key)
	}
	return obsolete, nil
}

func (f *Forwarder) invalidate(key relaySessionKey, session *tunnel.Session) error {
	f.mu.Lock()
	entry := f.sessions[key]
	if entry != nil && entry.session == session {
		delete(f.sessions, key)
	} else {
		entry = nil
	}
	f.mu.Unlock()
	if entry != nil {
		entry.cancel()
		f.reportSessionClosed(key, "local_invalidation", session.Err())
		started := time.Now()
		err := session.Close()
		f.observe("IngressForwardingCleanup", err, started)
		return err
	}
	return nil
}

func (f *Forwarder) observe(operation string, err error, started time.Time) {
	if f.observer != nil {
		f.observer.ObserveOperation(operation, err, time.Since(started))
	}
}

func (f *Forwarder) removeWhenDone(key relaySessionKey, entry *relaySession, session *tunnel.Session) {
	<-session.Done()
	f.mu.Lock()
	unexpected := !f.closed && f.sessions[key] == entry
	if unexpected {
		delete(f.sessions, key)
	}
	f.mu.Unlock()
	if unexpected {
		f.reportSessionClosed(key, "observed_close", session.Err())
	}
}

func (f *Forwarder) reportSessionClosed(key relaySessionKey, origin string, cause error) {
	if f.onSessionClosed != nil {
		f.onSessionClosed(key.relayServiceID, key.relayID, origin, cause)
	}
}

func closeRelaySessions(entries []*relaySession) error {
	var result error
	for _, entry := range entries {
		entry.cancel()
		select {
		case <-entry.ready:
			if entry.session != nil {
				result = errors.Join(result, entry.session.Close())
			}
		default:
		}
	}
	return result
}

type relayConnector interface {
	Connect(context.Context, relayTarget) (muxsession.Session, error)
	Credential() string
}

type tlsRelayConnector struct {
	tlsConfig       *tls.Config
	clusterSecret   string
	transportConfig muxsession.TLSYamuxConfig
}

func newTLSRelayConnector(tlsConfig *tls.Config, clusterSecret string, transportConfig muxsession.TLSYamuxConfig) (relayConnector, error) {
	if tlsConfig == nil || clusterSecret == "" {
		return nil, errors.New("ingress: forwarding TLS and cluster secret are required")
	}
	if tlsConfig.InsecureSkipVerify || tlsConfig.VerifyPeerCertificate != nil || tlsConfig.VerifyConnection != nil {
		return nil, errors.New("ingress: forwarding TLS verification must be configured by the forwarder")
	}
	return tlsRelayConnector{tlsConfig: tlsConfig.Clone(), clusterSecret: clusterSecret, transportConfig: transportConfig}, nil
}

func (c tlsRelayConnector) Connect(ctx context.Context, target relayTarget) (muxsession.Session, error) {
	tlsConfig := c.tlsConfig.Clone()
	return (muxsession.TLSYamuxConnector{
		TLSConfig: tlsConfig, Config: c.transportConfig,
	}).Connect(ctx, muxsession.Endpoint{Address: target.address, ServerName: target.serverName})
}

func (c tlsRelayConnector) Credential() string { return c.clusterSecret }
