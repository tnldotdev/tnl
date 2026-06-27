package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const claimIDPrefix = "claim_"

type PublisherConnectionController interface {
	ClaimPublisherConnection(context.Context, tunnelv1.PublisherConnectionRef, string, string) (relayv1.ClaimedPublisherConnection, error)
	MarkPublisherConnectionReady(context.Context, relayv1.ClaimedPublisherConnection) (relayv1.ClaimedPublisherConnection, error)
	DisconnectPublisherConnection(context.Context, relayv1.ClaimedPublisherConnection, bool) (relayv1.ClaimedPublisherConnection, error)
}

type PublisherAcceptorConfig struct {
	Control               PublisherConnectionController
	Registry              *Registry
	Select                func(string) (PublisherConnectionController, *Registry, bool)
	ReadyConnectionsDelta func(int)
	Report                func(error)
}

// PublisherAcceptor authenticates and owns publisher connections.
type PublisherAcceptor struct {
	control      PublisherConnectionController
	registry     *Registry
	selectTarget func(string) (PublisherConnectionController, *Registry, bool)
	readyDelta   func(int)
	report       func(error)
}

func NewPublisherAcceptor(config PublisherAcceptorConfig) (*PublisherAcceptor, error) {
	direct := config.Control != nil || config.Registry != nil
	if direct && (config.Control == nil || config.Registry == nil) || direct == (config.Select != nil) {
		return nil, errors.New("relay: publisher acceptor requires control and registry")
	}
	if config.Report == nil {
		config.Report = func(error) {}
	}
	if config.ReadyConnectionsDelta == nil {
		config.ReadyConnectionsDelta = func(int) {}
	}
	return &PublisherAcceptor{
		control: config.Control, registry: config.Registry, selectTarget: config.Select,
		readyDelta: config.ReadyConnectionsDelta, report: config.Report,
	}, nil
}

func (a *PublisherAcceptor) Accept(ctx context.Context, transport muxsession.Session) (retErr error) {
	var claimed relayv1.ClaimedPublisherConnection
	var connection *PublisherConnection
	ready := false
	control, registry := a.control, a.registry
	session, hello, err := tunnel.Accept(ctx, transport, func(authCtx context.Context, message tunnelv1.Message) error {
		if message.Role != tunnelv1.Publisher || message.PublisherConnection == nil {
			return &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
		}
		if a.selectTarget != nil {
			var ok bool
			control, registry, ok = a.selectTarget(message.PublisherConnection.RelayServiceID)
			if !ok || control == nil || registry == nil {
				return &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
			}
		}
		claimID, err := opaqueid.New(claimIDPrefix)
		if err != nil {
			return err
		}
		claimed, err = control.ClaimPublisherConnection(
			authCtx, *message.PublisherConnection, claimID, message.Credential,
		)
		if err != nil {
			return &tunnel.ProtocolError{Code: ControlErrorCode(err)}
		}
		return nil
	})
	registered := false
	defer func() {
		if ready {
			a.readyDelta(-1)
		}
		if registered {
			registry.Remove(connection)
		} else if session != nil {
			_ = session.Close()
		}
		if claimed.PublisherConnectionId != "" {
			disconnectCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			unexpected := retErr != nil && ctx.Err() == nil && !errors.Is(retErr, net.ErrClosed)
			_, disconnectErr := control.DisconnectPublisherConnection(disconnectCtx, claimed, unexpected)
			cancel()
			if disconnectErr != nil {
				a.report(fmt.Errorf("disconnect publisher connection %q: %w", claimed.PublisherConnectionId, disconnectErr))
			}
		}
	}()
	if err != nil {
		return err
	}
	connection, err = NewPublisherConnection(*hello.PublisherConnection, claimed, session)
	if err != nil {
		return err
	}
	if err := registry.Insert(connection); err != nil {
		_ = connection.Close()
		return err
	}
	registered = true
	claimed, err = control.MarkPublisherConnectionReady(ctx, claimed)
	if err != nil {
		return err
	}
	ready = true
	a.readyDelta(1)
	select {
	case <-ctx.Done():
		retErr = context.Cause(ctx)
	case <-session.Done():
		retErr = session.Err()
	}
	if errors.Is(retErr, muxsession.ErrClosed) || errors.Is(retErr, net.ErrClosed) {
		retErr = nil
	}
	return retErr
}
