package stream

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
)

// Session owns one prepared connector connection. applications cannot replace
// its selected run or extend its finite authority by opening another stream.
type Session struct {
	connection          *connectorConnection
	config              Config
	parent              context.Context
	once                sync.Once
	err                 error
	initialRelayAddress string
}

func (s *Session) Context() context.Context { return s.connection.ctx }

// SelectedRelayAddress observes slot zero of the actual signed pair retained at
// preparation. it does not predict a later failover or select another relay.
func (s *Session) SelectedRelayAddress() string { return s.initialRelayAddress }

// InnerCipherSuite observes the retained QUIC connection's negotiated cipher.
// it is diagnostic metadata, not a way to choose or replace connection trust.
func (s *Session) InnerCipherSuite() uint16 {
	return s.connection.connection.ConnectionState().TLS.CipherSuite
}

func (s *Session) Forward(ctx context.Context, local net.Conn) error {
	return s.connection.Forward(ctx, local)
}

func (s *Session) Close() error {
	s.once.Do(func() {
		if s.connection != nil {
			s.connection.Close()
		}
		cleanup := observability.Independent(context.WithoutCancel(s.parent))
		if s.config.CleanupContext != nil {
			cleanup = s.config.CleanupContext()
		}
		bounded, stop := context.WithTimeout(cleanup, 5*time.Second)
		defer stop()
		if closer, ok := s.config.Control.(interface{ CloseContext(context.Context) error }); ok {
			s.err = closer.CloseContext(bounded)
		} else if closer, ok := s.config.Control.(interface{ Close() error }); ok {
			s.err = closer.Close()
		}
	})
	return s.err
}
