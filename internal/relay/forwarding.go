package relay

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	serverhttp "github.com/tnldotdev/tnl/internal/serverhttp"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ForwardingAcceptorConfig struct {
	ServiceRegistry  *ServiceRegistry
	CurrentLease     func() relayv1.RelayLease
	ClusterSecrets   serverhttp.BearerSecrets
	StreamCapacity   int
	StreamsDelta     func(int)
	CapacityRejected func()
	StreamRejected   func(string)
	Now              func() time.Time
	Report           func(error)
	Observer         ForwardingObserver
}

// ForwardingAcceptor carries internal visitor streams from ingress to locally
// connected publishers. it never receives the ingress routing table.
type ForwardingAcceptor struct {
	registry         *ServiceRegistry
	currentLease     func() relayv1.RelayLease
	secrets          serverhttp.BearerSecrets
	streams          chan struct{}
	streamsDelta     func(int)
	capacityRejected func()
	streamRejected   func(string)
	now              func() time.Time
	report           func(error)
	observer         ForwardingObserver
}

func NewForwardingAcceptor(config ForwardingAcceptorConfig) (*ForwardingAcceptor, error) {
	if config.ServiceRegistry == nil || config.CurrentLease == nil || !config.ClusterSecrets.Valid() || config.StreamCapacity <= 0 {
		return nil, errors.New("relay: service registry, current lease, cluster secrets, and positive stream capacity are required")
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
		registry: config.ServiceRegistry, currentLease: config.CurrentLease, secrets: config.ClusterSecrets, streams: make(chan struct{}, config.StreamCapacity),
		streamsDelta: config.StreamsDelta, capacityRejected: config.CapacityRejected, streamRejected: config.StreamRejected,
		now: config.Now, report: config.Report, observer: config.Observer,
	}, nil
}

func (a *ForwardingAcceptor) Accept(ctx context.Context, transport muxsession.Session) error {
	session, _, err := tunnel.Accept(ctx, transport, func(_ context.Context, message tunnelv1.Message) error {
		if message.Role != tunnelv1.Ingress || !a.secrets.Matches(message.Credential) {
			return &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
		}
		return nil
	})
	if err != nil {
		return err
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
				incoming, err := session.AcceptServiceForwardingStream(acceptCtx)
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
					_ = incoming.Stream().Close()
					return
				}
				group.Go(func() {
					if err := a.forwardService(incoming.Context(), incoming); err != nil && acceptCtx.Err() == nil {
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
