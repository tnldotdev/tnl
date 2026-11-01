package ingress

import (
	"errors"
	"net"
	"sync"
)

const (
	DefaultClientHelloConnectionLimit = 1024
	DefaultControlConnectionLimit     = 1024
	DefaultRelayConnectionLimit       = 4096
	DefaultServiceConnectionLimit     = 256
)

type connectionKind uint8

const (
	visitorConnection connectionKind = iota
	pendingConnection
	controlConnection
	relayConnection
	serviceConnection
	connectionKinds
)

func admissionDefaults(config *Config) error {
	for _, setting := range []struct {
		value    *int
		fallback int
	}{
		{&config.MaxClientHelloConnections, DefaultClientHelloConnectionLimit},
		{&config.MaxControlConnections, DefaultControlConnectionLimit},
		{&config.MaxRelayConnections, DefaultRelayConnectionLimit},
		{&config.MaxServiceConnections, DefaultServiceConnectionLimit},
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

// admission classes share the short ClientHello inspection stage, not their
// long-lived capacity. map keys exist only while admitted.
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
	case pendingConnection:
		limit, resource = s.config.Pending.Connections, "denied_connections"
		if s.byDenied[key] >= s.config.Pending.PublicURLConnections {
			return nil, "denied_public_url_connections"
		}
	case controlConnection:
		limit, resource = s.config.MaxControlConnections, "control_connections"
	case relayConnection:
		limit, resource = s.config.MaxRelayConnections, "relay_tcp_connections"
	case serviceConnection:
		limit, resource = s.config.MaxServiceConnections, "public_service_connections"
	}
	if s.admitted[kind] >= limit {
		return nil, resource
	}
	s.admitted[kind]++
	s.reportAdmittedLocked()
	if kind == visitorConnection {
		s.byPublicURL[key]++
	} else if kind == pendingConnection {
		s.byDenied[key]++
	}
	return sync.OnceFunc(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.admitted[kind]--
		s.reportAdmittedLocked()
		var counts map[string]int
		if kind == visitorConnection {
			counts = s.byPublicURL
		} else if kind == pendingConnection {
			counts = s.byDenied
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
	for kind, class := range []string{"public", "denied", "control", "relay_tcp", "connector"} {
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

func (c *admittedConn) Close() error {
	err := c.readerConn.Close()
	c.release()
	return err
}

var _ net.Conn = (*admittedConn)(nil)
