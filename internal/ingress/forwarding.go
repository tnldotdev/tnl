package ingress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const relaySessionSetupTimeout = 10 * time.Second

// leave time for upgrade and authentication inside a visitor's 250ms relay budget.
const relayTransportFallbackDelay = 50 * time.Millisecond

type ForwarderConfig struct {
	Context         context.Context
	TLSConfig       *tls.Config
	ClusterSecret   string
	TransportConfig muxsession.WebSocketConfig
	// QUIC optionally supplies a borrowed transport; nil uses an owned UDP socket
	// per pooled connection. DisabledConnector selects WSS without opening UDP.
	QUIC            muxsession.Connector
	Observer        OperationObserver
	OnSessionClosed func(relayServiceID, relayID, origin string, cause error)
}

// Forwarder pools authenticated sessions to exact relay processes and waits for
// each internal-forwarding stream's acceptance before sending visitor bytes.
type Forwarder struct {
	connector       relayConnector
	quic            muxsession.Connector
	observer        OperationObserver
	context         context.Context
	cancel          context.CancelFunc
	onSessionClosed func(relayServiceID, relayID, origin string, cause error)

	mu        sync.Mutex
	sessions  map[relaySessionKey]*relaySession
	closed    bool
	closeDone chan struct{}
	closeErr  error
	workers   sync.WaitGroup
}

func NewForwarder(config ForwarderConfig) (*Forwarder, error) {
	connector, err := newWebSocketRelayConnector(config.TLSConfig, config.ClusterSecret, config.TransportConfig)
	if err != nil {
		return nil, err
	}
	f := newForwarderContext(config.Context, connector)
	f.quic = config.QUIC
	if f.quic == nil {
		f.quic = muxsession.OwnedQUICConnector{TLSConfig: config.TLSConfig.Clone()}
	}
	f.observer = config.Observer
	f.onSessionClosed = config.OnSessionClosed
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
	return &Forwarder{connector: connector, context: ctx, cancel: cancel, sessions: make(map[relaySessionKey]*relaySession)}
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
	f.workers.Wait()
	f.mu.Lock()
	result = errors.Join(result, f.closeErr)
	f.closeErr = result
	close(done)
	f.mu.Unlock()
	return result
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
		if err := context.Cause(ctx); err != nil {
			return nil, false, err
		}
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			return nil, false, net.ErrClosed
		}
		entry := f.sessions[key]
		created := false
		if entry == nil {
			if err := context.Cause(ctx); err != nil {
				f.mu.Unlock()
				return nil, false, err
			}
			obsolete, err := f.removeSupersededLocked(key)
			if err != nil {
				f.mu.Unlock()
				return nil, false, err
			}
			connectCtx, cancel := context.WithTimeout(f.context, relaySessionSetupTimeout)
			entry = &relaySession{ready: make(chan struct{}), cancel: cancel}
			f.sessions[key] = entry
			f.workers.Add(1)
			created = true
			f.mu.Unlock()
			if err := closeRelaySessions(obsolete); err != nil {
				f.mu.Lock()
				f.closeErr = errors.Join(f.closeErr, err)
				f.mu.Unlock()
			}
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
			f.invalidate(ctx, key, entry.session)
			continue
		default:
			return entry.session, !created, nil
		}
	}
}

func (f *Forwarder) connect(ctx context.Context, key relaySessionKey, target relayTarget, entry *relaySession) {
	defer f.workers.Done()
	ctx, finish := observability.Start(ctx, "ingress.relay_connect")
	started := time.Now()
	quic := f.quic
	if quic == nil {
		quic = muxsession.DisabledConnector{}
	}
	endpoint := muxsession.Endpoint{Address: target.address, ServerName: target.serverName}
	fallback := muxsession.ConnectorFunc(func(ctx context.Context, _ muxsession.Endpoint) (muxsession.Session, error) {
		return f.connector.Connect(ctx, target)
	})
	session, _, err := tunnel.Race(ctx,
		tunnel.Candidate{Connector: quic, Endpoint: endpoint, Transport: tunnel.TransportQUIC},
		tunnel.Candidate{Connector: fallback, Endpoint: endpoint, Transport: tunnel.TransportWSS},
		relayTransportFallbackDelay, tunnelv1.Message{
			Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Ingress,
			Credential: f.connector.Credential(),
		})
	entry.cancel()
	finish(err)
	f.observe(ctx, observability.OpIngressRelayConnect, err, started)

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
			cleanupErr := session.Close()
			f.mu.Lock()
			f.closeErr = errors.Join(f.closeErr, cleanupErr)
			f.mu.Unlock()
		}
		return
	}
	capacityErr := session.ServeServiceCapacity(f.context)
	cleanupErr := session.Close()
	// the pool reports and replaces a lost relay session. its observed terminal
	// read is not a failure of closing the recovered pool later. check after
	// joining the transport: quic can return that read error before publishing
	// its terminal cause. retain independent reads and owned stream cleanup.
	var streamCleanup *tunnel.SessionCleanupError
	if terminal := session.Err(); terminal != nil && !errors.As(capacityErr, &streamCleanup) && failure.Only(capacityErr, terminal) {
		select {
		case <-session.Done():
			capacityErr = nil
		default:
		}
	}
	f.mu.Lock()
	f.closeErr = errors.Join(f.closeErr, capacityErr, cleanupErr)
	f.mu.Unlock()
	f.removeWhenDone(key, entry, session)
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
			// service runs receive relay replacements independently. an older
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

func (f *Forwarder) invalidate(ctx context.Context, key relaySessionKey, session *tunnel.Session) error {
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
		f.observe(ctx, observability.OpIngressForwardingCleanup, err, started)
		return err
	}
	return nil
}

func (f *Forwarder) observe(ctx context.Context, operation observability.ServerOperation, err error, started time.Time) {
	if f.observer != nil {
		f.observer.ObserveOperationContext(ctx, operation, err, time.Since(started))
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

type webSocketRelayConnector struct {
	tlsConfig       *tls.Config
	clusterSecret   string
	transportConfig muxsession.WebSocketConfig
}

func newWebSocketRelayConnector(tlsConfig *tls.Config, clusterSecret string, transportConfig muxsession.WebSocketConfig) (relayConnector, error) {
	if tlsConfig == nil || clusterSecret == "" {
		return nil, errors.New("ingress: forwarding TLS and cluster secret are required")
	}
	if tlsConfig.InsecureSkipVerify || tlsConfig.VerifyPeerCertificate != nil || tlsConfig.VerifyConnection != nil {
		return nil, errors.New("ingress: forwarding TLS verification must be configured by the forwarder")
	}
	return webSocketRelayConnector{tlsConfig: tlsConfig.Clone(), clusterSecret: clusterSecret, transportConfig: transportConfig}, nil
}

func (c webSocketRelayConnector) Connect(ctx context.Context, target relayTarget) (muxsession.Session, error) {
	tlsConfig := c.tlsConfig.Clone()
	options := c.transportConfig
	options.DisableProxy = true
	return (muxsession.WebSocketConnector{
		TLSConfig: tlsConfig, Config: options,
	}).Connect(ctx, muxsession.Endpoint{Address: target.address, ServerName: target.serverName})
}

func (c webSocketRelayConnector) Credential() string { return c.clusterSecret }
