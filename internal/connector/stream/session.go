package stream

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"sync"
	"time"
)

// Session exposes the prepared connector engine without a machine-local listener.
// its caller owns the lifetime; Close joins streams, renewals and retirement.
type Session struct {
	connection *connectorConnection
	config     Config
	once       sync.Once
	err        error
}

// Prepare keeps the setup budget separate from the retained session lifetime.
// applications consume the same signed opening pool as native listeners.
func Prepare(lifetime, setup context.Context, config Config) (_ *Session, result error) {
	if lifetime == nil || setup == nil {
		return nil, ErrServiceConnection
	}
	if err := validateConfig(&config); err != nil {
		return nil, err
	}
	config.cleanup = newConnectorCleanup(lifetime, config.CleanupContext)
	owned := false
	defer func() {
		if !owned {
			if err := config.Control.Close(config.cleanup.context()); err != nil {
				result = errors.Join(result, &CleanupError{Err: err})
			}
			config.cleanup.close()
		}
	}()
	setup, stop := context.WithTimeout(setup, 30*time.Second)
	defer stop()
	signer, err := config.Control.ConnectorSigner(setup, config.IdentityID)
	if err != nil {
		return nil, err
	}
	if signer.Subject.Validate() != nil || signer.Subject.IdentityID != config.IdentityID || len(signer.PublicKey) != ed25519.PublicKeySize || signer.Sign == nil {
		return nil, ErrServiceConnection
	}
	connection, err := prepareConnectorConnection(lifetime, setup, config, signer)
	if err != nil {
		return nil, err
	}
	owned = true
	return &Session{connection: connection, config: config}, nil
}

func (s *Session) Context() context.Context { return s.connection.ctx }

func (s *Session) Forward(ctx context.Context, local net.Conn) error {
	if local == nil {
		return ErrServiceConnection
	}
	return newStdioOperation(ctx, local).forward(s.connection)
}

func (s *Session) Close() error {
	s.once.Do(func() {
		cleanup := s.config.cleanup
		defer cleanup.close()
		s.err = s.connection.Close(cleanup.context())
		if err := s.config.Control.Close(cleanup.context()); err != nil {
			s.err = errors.Join(s.err, &CleanupError{Err: err})
		}
	})
	return s.err
}
