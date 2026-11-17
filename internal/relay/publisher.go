package relay

import (
	"context"
	"errors"

	"github.com/tnldotdev/tnl/internal/observability"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type PublisherAcceptorConfig struct {
	Select                func(string) (ServicePublisherTarget, bool)
	ReadyConnectionsDelta func(int)
	ConnectionExited      func(bool)
	CapacityRejected      func()
	Report                func(error)
	Observer              OperationObserver
	Connector             func(string) (*ConnectorAcceptor, bool)
}

// PublisherAcceptor authenticates and owns publisher connections.
type PublisherAcceptor struct {
	selectTarget     func(string) (ServicePublisherTarget, bool)
	readyDelta       func(int)
	connectionExited func(bool)
	capacity         func()
	report           func(error)
	observer         OperationObserver
	connector        func(string) (*ConnectorAcceptor, bool)
}

func NewPublisherAcceptor(config PublisherAcceptorConfig) (*PublisherAcceptor, error) {
	if config.Select == nil {
		return nil, errors.New("relay: publisher acceptor requires a service target selector")
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
		selectTarget: config.Select,
		readyDelta:   config.ReadyConnectionsDelta, connectionExited: config.ConnectionExited,
		capacity: config.CapacityRejected, report: config.Report,
		observer:  config.Observer,
		connector: config.Connector,
	}, nil
}

func (a *PublisherAcceptor) Accept(ctx context.Context, transport muxsession.Session) (retErr error) {
	return a.AcceptSetup(ctx, ctx, transport, func() {})
}

// AcceptSetup releases pending capacity only after the hello has authenticated.
// setup bounds admission; ctx remains the owner of the established session.
func (a *PublisherAcceptor) AcceptSetup(ctx, setup context.Context, transport muxsession.Session, authenticated func()) (retErr error) {
	if authenticated == nil {
		return errors.New("relay: setup completion callback is required")
	}
	finishAdmission := startOperation(ctx, a.observer, observability.OpRelayAdmitPublisherConnection)
	var claimed *publisherClaim
	var connector *ConnectorAcceptor
	var connectorClaimed connectorClaim
	var releaseConnector func()
	defer func() {
		if releaseConnector != nil {
			releaseConnector()
		}
	}()
	session, hello, err := tunnel.AcceptWithResult(setup, transport, func(authCtx context.Context, message tunnelv1.Message) (*tunnelv1.ConnectorPairLegAccepted, error) {
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
		if message.Role != tunnelv1.Publisher || message.ServiceConnection == nil {
			return nil, &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
		}
		accepted, ok := transport.(muxsession.AcceptedPeer)
		if !ok {
			return nil, &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
		}
		source, err := newConnectorSocketSource(accepted)
		if err != nil {
			return nil, &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
		}
		claimed, err = a.claim(authCtx, message, source.ip)
		if err == nil {
			err = source.check()
		}
		var protocol *tunnel.ProtocolError
		if errors.As(err, &protocol) && protocol.Code == tunnelv1.CapacityExceeded {
			a.capacity()
		}
		return nil, err
	})
	if err == nil {
		authenticated()
	}
	if connector != nil {
		finishAdmission(err)
		if err != nil {
			return err
		}
		defer session.Close()
		return connector.serve(ctx, transport, session, *hello.ConnectorPairLegProof, connectorClaimed)
	}
	if claimed != nil {
		return claimed.serve(ctx, session, transport, a, err, finishAdmission)
	}
	finishAdmission(err)
	return err
}
