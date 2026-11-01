package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const claimIDPrefix = opaqueid.ClaimPrefix

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
	ConnectionExited      func(bool)
	CapacityRejected      func()
	Report                func(error)
	Observer              OperationObserver
	Private               *ServicePublisherAcceptor
	Connector             func(string) (*ConnectorAcceptor, bool)
}

// PublisherAcceptor authenticates and owns publisher connections.
type PublisherAcceptor struct {
	control          PublisherConnectionController
	registry         *Registry
	selectTarget     func(string) (PublisherConnectionController, *Registry, bool)
	readyDelta       func(int)
	connectionExited func(bool)
	capacity         func()
	report           func(error)
	observer         OperationObserver
	private          *ServicePublisherAcceptor
	connector        func(string) (*ConnectorAcceptor, bool)
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
	if config.CapacityRejected == nil {
		config.CapacityRejected = func() {}
	}
	if config.ConnectionExited == nil {
		config.ConnectionExited = func(bool) {}
	}
	return &PublisherAcceptor{
		control: config.Control, registry: config.Registry, selectTarget: config.Select,
		readyDelta: config.ReadyConnectionsDelta, connectionExited: config.ConnectionExited,
		capacity: config.CapacityRejected, report: config.Report,
		observer:  config.Observer,
		private:   config.Private,
		connector: config.Connector,
	}, nil
}

func (a *PublisherAcceptor) Accept(ctx context.Context, transport muxsession.Session) (retErr error) {
	finishAdmission := startOperation(ctx, a.observer, "RelayAdmitPublisherConnection")
	var claimed relayv1.ClaimedPublisherConnection
	var connection *PublisherConnection
	ready := false
	control, registry := a.control, a.registry
	var private *privateClaim
	var connector *ConnectorAcceptor
	var connectorClaimed connectorClaim
	var releaseConnector func()
	defer func() {
		if releaseConnector != nil {
			releaseConnector()
		}
	}()
	session, hello, err := tunnel.AcceptWithResult(ctx, transport, func(authCtx context.Context, message tunnelv1.Message) (*tunnelv1.ConnectorPairLegAccepted, error) {
		if message.Role == tunnelv1.Connector {
			if a.connector == nil || message.ConnectorPairLegProof == nil {
				return nil, &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
			}
			var ok bool
			connector, ok = a.connector(message.ConnectorPairLegProof.RelayServiceID)
			if !ok || connector == nil {
				return nil, &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
			}
			var err error
			releaseConnector, err = connector.reserve(*message.ConnectorPairLegProof)
			if err == nil {
				connectorClaimed, err = connector.claim(authCtx, transport, *message.ConnectorPairLegProof)
			}
			if err != nil {
				return nil, err
			}
			return &connectorClaimed.receipt, nil
		}
		if message.ServiceConnection != nil {
			var err error
			private, err = a.private.claim(authCtx, message)
			var protocol *tunnel.ProtocolError
			if errors.As(err, &protocol) && protocol.Code == tunnelv1.CapacityExceeded {
				a.capacity()
			}
			return nil, err
		}
		if message.Role != tunnelv1.Publisher || message.PublisherConnection == nil {
			return nil, &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
		}
		if a.selectTarget != nil {
			var ok bool
			control, registry, ok = a.selectTarget(message.PublisherConnection.RelayServiceID)
			if !ok || control == nil || registry == nil {
				return nil, &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
			}
		}
		claimID, err := opaqueid.New(claimIDPrefix)
		if err != nil {
			return nil, err
		}
		claimed, err = control.ClaimPublisherConnection(
			authCtx, *message.PublisherConnection, claimID, message.Credential,
		)
		if err != nil {
			return nil, a.controlError(err)
		}
		return nil, nil
	})
	if connector != nil {
		finishAdmission(err)
		if err != nil {
			return err
		}
		defer session.Close()
		return connector.serve(ctx, transport, session, *hello.ConnectorPairLegProof, connectorClaimed)
	}
	if private != nil {
		return errors.Join(err, private.serve(ctx, session, transport, a, finishAdmission))
	}
	registered := false
	// a successful claim must be disconnected with its exact identity, even if
	// registration or readiness fails. remove locally before notifying control.
	defer func() {
		if !ready {
			finishAdmission(retErr)
		}
		if ready {
			a.readyDelta(-1)
			a.connectionExited(retErr != nil && ctx.Err() == nil && !errors.Is(retErr, net.ErrClosed))
		}
		if registered {
			registry.Remove(connection)
		} else if session != nil {
			_ = session.Close()
		}
		if claimed.PublisherConnectionId != "" {
			disconnectCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			unexpected := retErr != nil && ctx.Err() == nil && !errors.Is(retErr, net.ErrClosed)
			finishDisconnect := startOperation(disconnectCtx, a.observer, "RelayDisconnectPublisherConnection")
			_, disconnectErr := control.DisconnectPublisherConnection(disconnectCtx, claimed, unexpected)
			finishDisconnect(disconnectErr)
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
	readyClaim, err := control.MarkPublisherConnectionReady(ctx, claimed)
	if err != nil {
		return err
	}
	claimed = readyClaim
	ready = true
	a.readyDelta(1)
	// admission ends after readiness; the connection and drain loop can outlive it.
	finishAdmission(nil)
	retErr = session.HandlePublisherDrain(ctx, connection.Drain)
	drained := retErr == nil
	if retErr == nil {
		select {
		case <-ctx.Done():
			retErr = context.Cause(ctx)
		case <-session.Done():
			retErr = session.Err()
		}
	} else if ctx.Err() != nil {
		retErr = context.Cause(ctx)
	} else {
		select {
		case <-session.Done():
			retErr = session.Err()
		default:
		}
	}
	if drained && (errors.Is(retErr, muxsession.ErrClosed) || errors.Is(retErr, net.ErrClosed) || errors.Is(retErr, io.EOF) || errors.Is(retErr, io.ErrClosedPipe)) {
		retErr = nil
	}
	return retErr
}

func (a *PublisherAcceptor) controlError(err error) error {
	return errors.Join(err, &tunnel.ProtocolError{Code: a.controlErrorCode(err)})
}

func (a *PublisherAcceptor) controlErrorCode(err error) tunnelv1.ErrorCode {
	code := ControlErrorCode(err)
	if code == tunnelv1.CapacityExceeded {
		a.capacity()
	}
	return code
}
