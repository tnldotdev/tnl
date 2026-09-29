package ingress

import (
	"errors"
	"net"
	"sync"
	"time"
)

const (
	DefaultClientHelloConnectionLimit       = 1024
	DefaultChallengeConnectionLimit         = 1024
	DefaultChallengeHostnameConnectionLimit = 8
	DefaultControlConnectionLimit           = 1024
	DefaultRelayConnectionLimit             = 4096
	DefaultDeniedConnectionLimit            = 16
	challengeConnectionTimeout              = 10 * time.Second
)

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
	} {
		if *setting.value == 0 {
			*setting.value = setting.fallback
		}
		if *setting.value < 0 {
			return errors.New("ingress: admission capacities must be positive")
		}
	}
	return nil
}

// Admission classes share the short ClientHello inspection stage, not their
// long-lived capacity. Map keys exist only while admitted.
func (s *Server) admitClass(kind connectionKind, key string) (release func(), rejected string) {
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
		if s.byPublicURL[key] >= max(1, s.config.MaxConnections/2) {
			return nil, "public_url_connections"
		}
	case deniedConnection:
		limit, resource = s.config.MaxDeniedConnections, "denied_connections"
		if s.byDenied[key] >= max(1, limit/2) {
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

func (s *Server) finishInspection() {
	s.mu.Lock()
	s.pending--
	s.mu.Unlock()
}

// The receiving HTTP/relay server owns a handed-off connection. Its class slot
// remains occupied until that owner closes it, even after ingress stops tracking
// it for drain. Preserve the readerConn's address and half-close behavior.
type admittedConn struct {
	*readerConn
	release func()
}

func (c *admittedConn) Close() error {
	err := c.readerConn.Close()
	c.release()
	return err
}

var _ net.Conn = (*admittedConn)(nil)
