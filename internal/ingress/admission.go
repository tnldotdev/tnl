package ingress

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const (
	DefaultClientHelloConnectionLimit       = 1024
	DefaultChallengeConnectionLimit         = 1024
	DefaultChallengeHostnameConnectionLimit = 8
	DefaultControlConnectionLimit           = 1024
	DefaultRelayConnectionLimit             = 4096
	DefaultDeniedConnectionLimit            = 16
	DefaultPendingConnectionBytes           = 64 << 10
	DefaultPendingURLConnectionLimit        = 8
	DefaultPendingSourceConnectionLimit     = 4
	DefaultPendingURLRate                   = 10
	DefaultPendingURLBurst                  = 20
	DefaultPendingSourceRate                = 10
	DefaultPendingSourceBurst               = 20
	challengeConnectionTimeout              = 10 * time.Second
)

var errPendingBytes = errors.New("ingress: pending authorization byte budget exhausted")

type connectionKind uint8

const (
	visitorConnection connectionKind = iota
	deniedConnection
	challengeConnection
	controlConnection
	relayConnection
	connectionKinds
)

func admissionDefaults(config *Config) error {
	for _, setting := range []struct {
		value    *int
		fallback int
	}{
		{&config.MaxClientHelloConnections, DefaultClientHelloConnectionLimit},
		{&config.MaxChallengeConnections, DefaultChallengeConnectionLimit},
		{&config.MaxHostnameChallengeConnections, DefaultChallengeHostnameConnectionLimit},
		{&config.MaxControlConnections, DefaultControlConnectionLimit},
		{&config.MaxRelayConnections, DefaultRelayConnectionLimit},
		{&config.MaxDeniedConnections, DefaultDeniedConnectionLimit},
		{&config.MaxPendingSourceConnections, DefaultPendingSourceConnectionLimit},
		{&config.PendingConnectionBytes, DefaultPendingConnectionBytes},
		{&config.PendingURLRate, DefaultPendingURLRate},
		{&config.PendingURLBurst, DefaultPendingURLBurst},
		{&config.PendingSourceRate, DefaultPendingSourceRate},
		{&config.PendingSourceBurst, DefaultPendingSourceBurst},
	} {
		if *setting.value == 0 {
			*setting.value = setting.fallback
		}
		if *setting.value < 0 {
			return errors.New("ingress: admission capacities must be positive")
		}
	}
	if config.MaxPendingURLConnections == 0 {
		config.MaxPendingURLConnections = min(DefaultPendingURLConnectionLimit, max(1, config.MaxDeniedConnections/2))
	}
	if config.MaxPendingURLConnections < 0 || config.MaxPendingURLConnections > config.MaxDeniedConnections ||
		config.PendingConnectionBytes > 1<<20 {
		return errors.New("ingress: pending visitor limits exceed the configured safety bounds")
	}
	return nil
}

func (s *Server) admitPending(key, source string, selected int) (func(), string) {
	s.mu.Lock()
	if s.byPendingSource[source] >= s.config.MaxPendingSourceConnections {
		s.mu.Unlock()
		return nil, "pending_source_connections"
	}
	s.byPendingSource[source]++
	s.mu.Unlock()
	release, reason := s.admitClass(deniedConnection, key, selected)
	if release == nil {
		s.releasePendingSource(source)
		return nil, reason
	}
	return sync.OnceFunc(func() {
		release()
		s.releasePendingSource(source)
	}), ""
}

func pendingSourceNetwork(address netip.Addr) string {
	if !address.IsValid() || address.Zone() != "" {
		return ""
	}
	address = address.Unmap()
	bits := address.BitLen()
	if address.Is6() {
		bits = 64
	}
	return netip.PrefixFrom(address, bits).Masked().String()
}

func (s *Server) releasePendingSource(source string) {
	s.mu.Lock()
	s.byPendingSource[source]--
	if s.byPendingSource[source] == 0 {
		delete(s.byPendingSource, source)
	}
	s.mu.Unlock()
}

// admission classes share the short ClientHello inspection stage, not their
// long-lived capacity. map keys exist only while admitted.
func (s *Server) admitClass(kind connectionKind, key string, selected ...int) (release func(), rejected string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return nil, "draining"
	}
	var limit int
	var resource string
	switch kind {
	case visitorConnection:
		limit, resource = s.config.MaxConnections, "public_connections"
		urlLimit := s.config.Traffic.Default.Connections
		if len(selected) != 0 {
			urlLimit = selected[0]
		}
		if s.byPublicURL[key] >= min(urlLimit, max(1, s.config.MaxConnections/2)) {
			return nil, "public_url_connections"
		}
	case deniedConnection:
		limit, resource = s.config.MaxDeniedConnections, "denied_connections"
		if s.byDenied[key] >= s.config.MaxPendingURLConnections {
			return nil, "denied_public_url_connections"
		}
	case challengeConnection:
		limit, resource = s.config.MaxChallengeConnections, "challenge_connections"
		if s.byChallenge[key] >= s.config.MaxHostnameChallengeConnections {
			return nil, "challenge_hostname_connections"
		}
	case controlConnection:
		limit, resource = s.config.MaxControlConnections, "control_connections"
	case relayConnection:
		limit, resource = s.config.MaxRelayConnections, "relay_tcp_connections"
	}
	if s.admitted[kind] >= limit {
		return nil, resource
	}
	s.admitted[kind]++
	s.reportAdmittedLocked()
	if kind == visitorConnection {
		s.byPublicURL[key]++
	} else if kind == deniedConnection {
		s.byDenied[key]++
	} else if kind == challengeConnection {
		s.byChallenge[key]++
	}
	return sync.OnceFunc(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.admitted[kind]--
		s.reportAdmittedLocked()
		var counts map[string]int
		if kind == visitorConnection {
			counts = s.byPublicURL
		} else if kind == deniedConnection {
			counts = s.byDenied
		} else if kind == challengeConnection {
			counts = s.byChallenge
		}
		if counts != nil {
			counts[key]--
			if counts[key] == 0 {
				delete(counts, key)
			}
		}
	}), ""
}

func (s *Server) rejectCapacity(resource string) {
	if s.config.Metrics != nil {
		s.config.Metrics.IncCapacityRejection(resource)
	}
}

// call only with mu held so a later update cannot overwrite a newer count.
func (s *Server) reportAdmittedLocked() {
	if s.config.Metrics == nil {
		return
	}
	for kind, class := range []string{"public", "denied", "challenge", "control", "relay_tcp"} {
		s.config.Metrics.SetIngressConnections(class, s.admitted[kind])
	}
}

func (s *Server) finishInspection() {
	s.mu.Lock()
	s.pending--
	if s.config.Metrics != nil {
		s.config.Metrics.SetIngressConnections("client_hello", s.pending)
	}
	s.mu.Unlock()
}

// the receiving HTTP or relay server owns a handed-off connection. its class slot
// remains occupied until that owner closes it, even after ingress stops tracking
// it for drain. preserve the readerConn's address and half-close behavior.
type admittedConn struct {
	*readerConn
	release func()
}

// classTicket transfers one visitor from pending to ordinary capacity only
// after the ordinary connection slot and new-connection token are available.
type classTicket struct {
	mu               sync.Mutex
	release          func()
	closed           bool
	promoted         bool
	deadline         time.Time
	pendingBytes     int
	pendingByteLimit int
	public           net.Conn
	upstream         net.Conn
}

func (t *classTicket) setPendingDeadline(public, upstream net.Conn) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return net.ErrClosed
	}
	t.public, t.upstream = public, upstream
	if t.promoted {
		return nil
	}
	return errors.Join(public.SetDeadline(t.deadline), upstream.SetDeadline(t.deadline))
}

func (t *classTicket) pendingBytesAllowed(size int) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || !t.deadline.IsZero() && !t.deadline.After(time.Now()) {
		return net.ErrClosed
	}
	if t.promoted {
		return nil
	}
	limit := t.pendingByteLimit
	if limit == 0 {
		limit = DefaultPendingConnectionBytes
	}
	if size > limit-t.pendingBytes {
		return errPendingBytes
	}
	t.pendingBytes += size
	return nil
}

func (t *classTicket) promote(s *Server, key trafficKey, limits TrafficLimits) tunnelv1.AdmissionResult {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || t.promoted {
		return tunnelv1.AdmissionResult{Type: tunnelv1.StreamRejected, Code: tunnelv1.StaleConnectionAssignment}
	}
	release, resource := s.admitClass(visitorConnection, key.url, limits.Connections)
	if release == nil {
		s.rejectCapacity(resource)
		return tunnelv1.AdmissionResult{Type: tunnelv1.StreamRejected, Code: tunnelv1.CapacityExceeded}
	}
	if !s.traffic.allowConnection(key, limits) {
		release()
		s.rejectCapacity("public_url_connection_rate")
		return tunnelv1.AdmissionResult{Type: tunnelv1.StreamRejected, Code: tunnelv1.CapacityExceeded}
	}
	if t.public != nil {
		if err := errors.Join(t.public.SetDeadline(time.Time{}), t.upstream.SetDeadline(time.Time{})); err != nil {
			release()
			return tunnelv1.AdmissionResult{Type: tunnelv1.StreamRejected, Code: tunnelv1.Unavailable}
		}
	}
	t.release()
	t.release, t.promoted = release, true
	return tunnelv1.AdmissionResult{Type: tunnelv1.StreamAccepted}
}

func (t *classTicket) isPromoted() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.promoted
}

func (t *classTicket) close() {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	release := t.release
	t.mu.Unlock()
	release()
}

func (c *admittedConn) Close() error {
	err := c.readerConn.Close()
	c.release()
	return err
}

var _ net.Conn = (*admittedConn)(nil)
