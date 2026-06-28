package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/internal/streamcopy"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ForwardingAcceptorConfig struct {
	Registry       *Registry
	ClusterSecrets serviceapi.BearerSecrets
	StreamCapacity int
	Now            func() time.Time
	Report         func(error)
}

// ForwardingAcceptor carries internal visitor streams from ingress to locally
// connected publishers. It never receives the ingress routing table.
type ForwardingAcceptor struct {
	registry *Registry
	secrets  serviceapi.BearerSecrets
	streams  chan struct{}
	now      func() time.Time
	report   func(error)
}

func NewForwardingAcceptor(config ForwardingAcceptorConfig) (*ForwardingAcceptor, error) {
	if config.Registry == nil || !config.ClusterSecrets.Valid() || config.StreamCapacity <= 0 {
		return nil, errors.New("relay: forwarding registry, cluster secrets, and positive stream capacity are required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Report == nil {
		config.Report = func(error) {}
	}
	return &ForwardingAcceptor{
		registry: config.Registry, secrets: config.ClusterSecrets, streams: make(chan struct{}, config.StreamCapacity),
		now: config.Now, report: config.Report,
	}, nil
}

func (a *ForwardingAcceptor) Accept(ctx context.Context, transport muxsession.Session) error {
	session, hello, err := tunnel.Accept(ctx, transport, func(_ context.Context, message tunnelv1.Message) error {
		if message.Role != tunnelv1.Ingress || !a.secrets.Matches(message.Credential) {
			return &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if hello.Role != tunnelv1.Ingress {
		_ = session.Close()
		return &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
	}
	defer session.Close()
	var group sync.WaitGroup
	defer group.Wait()
	for {
		incoming, err := session.AcceptInternalForwardingStream(ctx)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, muxsession.ErrClosed) {
				return nil
			}
			return err
		}
		group.Add(1)
		go func() {
			defer group.Done()
			if err := a.forward(ctx, incoming); err != nil && ctx.Err() == nil {
				a.report(err)
			}
		}()
	}
}

func (a *ForwardingAcceptor) forward(ctx context.Context, incoming *tunnel.IncomingInternalForwardingStream) error {
	select {
	case a.streams <- struct{}{}:
		defer func() { <-a.streams }()
	default:
		return incoming.Reject(tunnelv1.CapacityExceeded)
	}
	connection, ok := a.registry.Candidate(incoming.Header, a.now())
	if !ok {
		return incoming.Reject(tunnelv1.StaleConnectionAssignment)
	}
	publisher, err := connection.OpenVisitor(ctx, incoming.Header.VisitorConnectionID)
	if err != nil {
		code := tunnelv1.Unavailable
		var protocolError *tunnel.ProtocolError
		if errors.As(err, &protocolError) {
			code = protocolError.Code
		}
		return errors.Join(incoming.Reject(code), err)
	}
	defer publisher.Close()
	if err := incoming.Accept(); err != nil {
		return err
	}
	defer incoming.Stream.Close()
	if _, err := streamcopy.Copy(incoming.Stream, publisher); err != nil {
		return fmt.Errorf("relay: forward visitor connection %s: %w", incoming.Header.VisitorConnectionID, err)
	}
	return nil
}
