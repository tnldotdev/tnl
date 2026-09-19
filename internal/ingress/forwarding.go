package ingress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/routebackend"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ForwarderConfig struct {
	TLSConfig       *tls.Config
	ClusterSecret   string
	TransportConfig muxsession.TLSYamuxConfig
}

// Forwarder pools authenticated sessions to exact relay processes and creates
// route backends that open acknowledged internal-forwarding streams.
type Forwarder struct {
	connector relayConnector

	mu        sync.Mutex
	sessions  map[relaySessionKey]*relaySession
	closed    bool
	closeDone chan struct{}
	closeErr  error
}

func NewForwarder(config ForwarderConfig) (*Forwarder, error) {
	connector, err := newTLSRelayConnector(config.TLSConfig, config.ClusterSecret, config.TransportConfig)
	if err != nil {
		return nil, err
	}
	return newForwarder(connector), nil
}

func newForwarder(connector relayConnector) *Forwarder {
	return &Forwarder{connector: connector, sessions: make(map[relaySessionKey]*relaySession)}
}

// Backends preserves control's publisher-connection order. Every returned
// backend is bound to the route version, assignment, and concrete relay lease
// represented by entry.
func (f *Forwarder) Backends(entry ingressv1.IngressRoutingTableEntry) ([]routebackend.Backend, error) {
	if f == nil || f.connector == nil {
		return nil, errors.New("ingress: forwarding connector is required")
	}
	if entry.RouteVersion <= 0 {
		return nil, errors.New("ingress: forwarding route version is invalid")
	}
	backends := make([]routebackend.Backend, 0, len(entry.PublisherConnections))
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
			VisitorConnectionID: "visitor", RouteID: entry.RouteId, RouteSessionID: entry.RouteSessionId,
			RouteVersion: uint64(entry.RouteVersion), PublisherConnectionID: connection.PublisherConnectionId,
			ConnectionSlot:               uint8(connection.ConnectionSlot),
			ConnectionAssignmentRevision: uint64(connection.ConnectionAssignmentRevision),
			RelayServiceID:               connection.RelayServiceId, RelayID: connection.RelayId,
			RelayRunID: connection.RelayRunId, RelayLeaseRevision: uint64(connection.RelayLeaseRevision),
			RouteExpiresAt: entry.RouteExpiresAt, LeaseExpiresAt: connection.LeaseExpiresAt,
		}
		if err := header.Validate(); err != nil {
			return nil, fmt.Errorf("ingress: forwarding publisher connection is invalid: %w", err)
		}
		header.VisitorConnectionID = ""
		backends = append(backends, forwardingBackend{forwarder: f, target: target, header: header})
	}
	return backends, nil
}

// Route converts one validated routing-table projection into the immutable
// per-visitor route consumed by Server.
func (f *Forwarder) Route(entry ingressv1.IngressRoutingTableEntry) (Route, error) {
	backends, err := f.Backends(entry)
	if err != nil {
		return Route{}, err
	}
	prefixes := make([]netip.Prefix, 0, len(entry.AllowedIpPrefixes))
	for _, value := range entry.AllowedIpPrefixes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix != prefix.Masked() {
			return Route{}, errors.New("ingress: routing-table IP prefix is invalid")
		}
		prefixes = append(prefixes, prefix)
	}
	if entry.IpPolicy == ingressv1.AllowAll && len(prefixes) != 0 ||
		entry.IpPolicy == ingressv1.Allowlist && len(prefixes) == 0 {
		return Route{}, errors.New("ingress: routing-table IP policy is inconsistent")
	}
	route := Route{
		ID: entry.RouteId, RouteVersion: uint64(entry.RouteVersion),
		AllowedIPPrefixes: prefixes, Backends: backends,
	}
	if entry.RecoveryEpisodeId != nil && *entry.RecoveryEpisodeId > 0 {
		route.RecoveryEpisodeID = uint64(*entry.RecoveryEpisodeId)
	}
	return route, nil
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

// Open waits for relay acceptance after the visitor stream is acknowledged.
// The caller owns the returned stream, not the pooled session. Acceptance does
// not establish route TLS or prove local-service health.
func (b forwardingBackend) Open(ctx context.Context, visitorConnectionID string) (net.Conn, error) {
	header := b.header
	header.VisitorConnectionID = visitorConnectionID
	if err := header.Validate(); err != nil {
		return nil, fmt.Errorf("ingress: internal forwarding header: %w", err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		session, reused, err := b.forwarder.session(ctx, b.target)
		if err != nil {
			return nil, err
		}
		stream, err := session.OpenInternalForwardingStream(ctx, header)
		if err == nil {
			return stream, nil
		}
		var protocolError *tunnel.ProtocolError
		if errors.As(err, &protocolError) {
			return nil, err
		}
		b.forwarder.invalidate(b.target.key(), session)
		if !reused {
			return nil, fmt.Errorf("ingress: open internal forwarding stream: %w", err)
		}
	}
	panic("unreachable")
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
		if entry := f.sessions[key]; entry != nil {
			ready := entry.ready
			f.mu.Unlock()
			select {
			case <-ready:
			case <-ctx.Done():
				return nil, false, context.Cause(ctx)
			}
			if entry.err != nil {
				return nil, false, entry.err
			}
			select {
			case <-entry.session.Done():
				f.invalidate(key, entry.session)
				continue
			default:
				return entry.session, true, nil
			}
		}

		connectCtx, cancel := context.WithCancel(ctx)
		entry := &relaySession{ready: make(chan struct{}), cancel: cancel}
		obsolete := f.removeSupersededLocked(key)
		f.sessions[key] = entry
		f.mu.Unlock()
		_ = closeRelaySessions(obsolete)

		transport, err := f.connector.Connect(connectCtx, target)
		var session *tunnel.Session
		if err == nil {
			session, err = tunnel.Dial(connectCtx, transport, tunnelv1.Message{
				Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Ingress,
				Credential: f.connector.Credential(),
			})
		}
		cancel()

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
			return nil, false, fmt.Errorf("ingress: connect to relay process: %w", err)
		}
		go f.removeWhenDone(key, entry, session)
		return session, false, nil
	}
}

func (f *Forwarder) removeSupersededLocked(current relaySessionKey) []*relaySession {
	var obsolete []*relaySession
	for key, entry := range f.sessions {
		if key != current && key.relayServiceID == current.relayServiceID && key.relayID == current.relayID {
			delete(f.sessions, key)
			obsolete = append(obsolete, entry)
		}
	}
	return obsolete
}

func (f *Forwarder) invalidate(key relaySessionKey, session *tunnel.Session) {
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
		_ = session.Close()
	}
}

func (f *Forwarder) removeWhenDone(key relaySessionKey, entry *relaySession, session *tunnel.Session) {
	<-session.Done()
	f.mu.Lock()
	if f.sessions[key] == entry {
		delete(f.sessions, key)
	}
	f.mu.Unlock()
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
