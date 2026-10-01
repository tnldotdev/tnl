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
	"github.com/tnldotdev/tnl/pkg/api/relayv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ForwardingAcceptorConfig struct {
	Registry         *Registry
	CurrentLease     func() relayv1.RelayLease
	ClusterSecrets   serviceapi.BearerSecrets
	StreamCapacity   int
	StreamsDelta     func(int)
	CapacityRejected func()
	StreamRejected   func(string)
	Now              func() time.Time
	Report           func(error)
	Observer         OperationObserver
}

// ForwardingAcceptor carries internal visitor streams from ingress to locally
// connected publishers. it never receives the ingress routing table.
type ForwardingAcceptor struct {
	registry         *Registry
	currentLease     func() relayv1.RelayLease
	secrets          serviceapi.BearerSecrets
	streams          chan struct{}
	streamsDelta     func(int)
	capacityRejected func()
	streamRejected   func(string)
	now              func() time.Time
	report           func(error)
	observer         OperationObserver
}

func NewForwardingAcceptor(config ForwardingAcceptorConfig) (*ForwardingAcceptor, error) {
	if config.Registry == nil || config.CurrentLease == nil || !config.ClusterSecrets.Valid() || config.StreamCapacity <= 0 {
		return nil, errors.New("relay: forwarding registry, current lease, cluster secrets, and positive stream capacity are required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Report == nil {
		config.Report = func(error) {}
	}
	if config.StreamsDelta == nil {
		config.StreamsDelta = func(int) {}
	}
	if config.CapacityRejected == nil {
		config.CapacityRejected = func() {}
	}
	if config.StreamRejected == nil {
		config.StreamRejected = func(string) {}
	}
	return &ForwardingAcceptor{
		registry: config.Registry, currentLease: config.CurrentLease, secrets: config.ClusterSecrets, streams: make(chan struct{}, config.StreamCapacity),
		streamsDelta: config.StreamsDelta, capacityRejected: config.CapacityRejected, streamRejected: config.StreamRejected,
		now: config.Now, report: config.Report,
		observer: config.Observer,
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
	// bounded concurrent header readers keep one slow ingress stream from
	// blocking others on the same ingress session. accepted streams run independently.
	const headerReaders = 4
	acceptCtx, cancel := context.WithCancel(ctx)
	var group sync.WaitGroup
	defer func() {
		cancel()
		_ = session.Close()
		group.Wait()
	}()
	results := make(chan error, headerReaders)
	for range headerReaders {
		group.Go(func() {
			for {
				incoming, err := session.AcceptInternalForwardingStream(acceptCtx)
				if err != nil {
					var headerErr *tunnel.StreamHeaderError
					if errors.As(err, &headerErr) {
						if acceptCtx.Err() == nil {
							a.report(err)
						}
						continue
					}
					results <- err
					return
				}
				if acceptCtx.Err() != nil {
					_ = incoming.Stream.Close()
					return
				}
				group.Go(func() {
					if err := a.forward(acceptCtx, incoming); err != nil && acceptCtx.Err() == nil {
						a.report(err)
					}
				})
			}
		})
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-results:
		if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, muxsession.ErrClosed) {
			return nil
		}
		return err
	}
}

func (a *ForwardingAcceptor) forward(ctx context.Context, incoming *tunnel.IncomingInternalForwardingStream) (retErr error) {
	finishOpen := startOperation(ctx, a.observer, "RelayOpenVisitorStream")
	opened := false
	var rejected error
	defer func() {
		if !opened {
			finishOpen(errors.Join(retErr, rejected))
		}
	}()
	if !a.acquireStream() {
		rejected = &tunnel.ProtocolError{Code: tunnelv1.CapacityExceeded}
		return incoming.Reject(tunnelv1.CapacityExceeded)
	}
	defer a.releaseStream()
	connection, ok := a.registry.Candidate(incoming.Header, a.currentLease(), a.now())
	if !ok {
		a.streamRejected("stale_assignment")
		rejected = &tunnel.ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
		return incoming.Reject(tunnelv1.StaleConnectionAssignment)
	}
	openVisitor := connection.OpenVisitor
	if incoming.Header.IPPolicyDenied {
		openVisitor = connection.OpenDeniedVisitor
	}
	publisher, err := openVisitor(ctx, incoming.Header.VisitorConnectionID)
	if err != nil {
		a.streamRejected("publisher_unavailable")
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
	opened = true
	finishOpen(nil)
	defer incoming.Stream.Close()
	if _, err := streamcopy.Copy(incoming.Stream, publisher); err != nil {
		return fmt.Errorf("relay: forward visitor connection %s: %w", incoming.Header.VisitorConnectionID, err)
	}
	return nil
}

func (a *ForwardingAcceptor) acquireStream() bool {
	select {
	case a.streams <- struct{}{}:
		a.streamsDelta(1)
		return true
	default:
		a.capacityRejected()
		return false
	}
}

func (a *ForwardingAcceptor) releaseStream() {
	<-a.streams
	a.streamsDelta(-1)
}
