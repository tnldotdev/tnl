package relay

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	relayv1 "github.com/tnldotdev/tnl/pkg/api/control/private/relay/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func serviceAcceptorFixture(t *testing.T, client *privateClaimControlStub, configure func(*PublisherAcceptorConfig)) (*PublisherAcceptor, tunnelv1.Message, *ServiceRegistry) {
	t.Helper()
	header := privateLifecycleHeader()
	ref := tunnel.ServiceForwardingRef(header)
	controller := &Controller{client: client, now: time.Now, lease: relayv1.RelayLease{
		RelayServiceId: ref.RelayServiceID, RelayId: header.RelayID, RelayRunId: header.RelayRunID,
		RelayLeaseRevision: int64(header.RelayLeaseRevision), LeaseExpiresAt: header.LeaseExpiresAt,
	}}
	registry := NewServiceRegistry()
	t.Cleanup(func() { _ = registry.Close() })
	config := PublisherAcceptorConfig{Select: func(id string) (ServicePublisherTarget, bool) {
		return ServicePublisherTarget{Control: controller, Registry: registry}, id == ref.RelayServiceID
	}}
	if configure != nil {
		configure(&config)
	}
	acceptor, err := NewPublisherAcceptor(config)
	if err != nil {
		t.Fatal(err)
	}
	return acceptor, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Publisher,
		Credential: "publisher-credential", ServiceConnection: &ref}, registry
}

func TestPublisherAcceptorRejectsPublisherHelloWithoutServiceConnection(t *testing.T) {
	client := &privateClaimControlStub{}
	var selections int
	acceptor, hello, _ := serviceAcceptorFixture(t, client, func(config *PublisherAcceptorConfig) {
		config.Select = func(string) (ServicePublisherTarget, bool) {
			selections++
			return ServicePublisherTarget{}, false
		}
	})
	hello.ServiceConnection = nil
	session, done, err := dialPrivateClaim(t, acceptor.Accept, hello)
	if session != nil || err == nil {
		t.Fatal("publisher hello without a service connection was accepted")
	}
	relayAwait(t, done)
	if selections != 0 || client.claims.Load() != 0 || client.ready.Load() != 0 {
		t.Fatal("publisher hello without a service connection reached authority")
	}
}

func TestPublisherClaimFailedHandshakeDisconnectsOnceAndKeepsBothErrors(t *testing.T) {
	metrics := observability.New("relay")
	disconnectErr := errors.New("exact claim disconnect failed")
	var disconnects atomic.Int64
	client := &privateClaimControlStub{disconnectErr: disconnectErr}
	acceptor, hello, registry := serviceAcceptorFixture(t, client, func(config *PublisherAcceptorConfig) {
		config.Observer = metrics
	})
	claim, err := acceptor.claim(t.Context(), hello, netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	client.disconnect = func(ctx context.Context, id string, body relayv1.ServicePublisherConnectionTransition) {
		disconnects.Add(1)
		want := relayv1.ServicePublisherConnectionTransition{
			Unexpected:   body.Unexpected,
			ServiceRunId: claim.ref.ServiceRunID, RunNumber: int64(claim.ref.RunNumber),
			ConnectionAssignmentRevision: int64(claim.ref.ConnectionAssignmentRevision),
			RelayId:                      claim.lease.RelayId, RelayRunId: claim.lease.RelayRunId, RelayLeaseRevision: claim.lease.RelayLeaseRevision,
		}
		if id != claim.ref.PublisherConnectionID || body.Unexpected == nil || *body.Unexpected || body != want {
			t.Error("failed handshake disconnected another assignment or relay lease")
		}
		deadline, bounded := ctx.Deadline()
		if ctx.Err() != nil || !bounded || time.Until(deadline) > 10*time.Second {
			t.Error("disconnect inherited cancellation or lost its cleanup deadline")
		}
	}
	// cleanup uses the captured claim even after the process lease has changed.
	claim.target.Control.mu.Lock()
	claim.target.Control.lease.RelayRunId += "-restarted"
	claim.target.Control.lease.RelayLeaseRevision++
	claim.target.Control.mu.Unlock()
	admissionErr := errors.Join(context.Canceled, errors.New("publisher acceptance failed"))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err = claim.serve(ctx, nil, nil, acceptor, admissionErr, startOperation(ctx, metrics, observability.OpRelayAdmitPublisherConnection))
	if !errors.Is(err, admissionErr) || !errors.Is(err, disconnectErr) || disconnects.Load() != 1 || client.ready.Load() != 0 {
		t.Fatal("failed handshake lost its error, reached ready, or disconnected more than once", err)
	}
	assertRelayOperation(t, metrics, "RelayDisconnectPublisherConnection", "error", 1)
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if len(registry.claims) != 0 {
		t.Fatal("disconnect completion retained its local claim reservation")
	}
}

func TestPublisherAcceptorReadyFailureRemovesRegistrationAndDisconnects(t *testing.T) {
	readyErr := errors.New("ready request failed")
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock)
	var disconnects, readyConnections atomic.Int64
	client := &privateClaimControlStub{
		readyErr:    readyErr,
		beforeReady: func() { <-release },
		disconnect: func(context.Context, string, relayv1.ServicePublisherConnectionTransition) {
			disconnects.Add(1)
		},
	}
	acceptor, hello, registry := serviceAcceptorFixture(t, client, func(config *PublisherAcceptorConfig) {
		config.ReadyConnectionsDelta = func(delta int) { readyConnections.Add(int64(delta)) }
	})
	session, done, err := dialPrivateClaim(t, acceptor.Accept, hello)
	if err != nil || session == nil {
		t.Fatal("publisher handshake did not reach the readiness boundary", err)
	}
	unblock()
	if err := relayAwait(t, done); !errors.Is(err, readyErr) {
		t.Fatal("readiness cleanup lost the control failure", err)
	}
	if client.ready.Load() != 1 || disconnects.Load() != 1 || readyConnections.Load() != 0 {
		t.Fatal("failed readiness leaked a ready connection or disconnected more than once")
	}
	if connections, streams := registry.Load(); connections != 0 || streams != 0 {
		t.Fatal("failed readiness retained local registration or stream capacity", connections, streams)
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if len(registry.claims) != 0 {
		t.Fatal("failed readiness retained the exact local claim")
	}
}

func TestPublisherDisconnectDistinguishesLossFromDrainAndCleanupFailure(t *testing.T) {
	for _, mode := range []string{"loss", "publisher-drain", "relay-drain", "canceled", "failed-cleanup"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			ready := make(chan struct{}, 1)
			disconnected := make(chan relayv1.ServicePublisherConnectionTransition, 1)
			client := &privateClaimControlStub{disconnect: func(_ context.Context, _ string, body relayv1.ServicePublisherConnectionTransition) {
				disconnected <- body
			}}
			cleanupErr := errors.New("disconnect cleanup failed")
			if mode == "failed-cleanup" {
				client.disconnectErr = cleanupErr
			}
			acceptor, hello, registry := serviceAcceptorFixture(t, client, func(config *PublisherAcceptorConfig) {
				config.ReadyConnectionsDelta = func(delta int) {
					if delta > 0 {
						ready <- struct{}{}
					}
				}
			})
			session, done, err := dialPrivateClaim(t, func(_ context.Context, outer muxsession.Session) error {
				return acceptor.Accept(ctx, outer)
			}, hello)
			if err != nil {
				t.Fatal(err)
			}
			relayAwait(t, ready)
			switch mode {
			case "publisher-drain", "failed-cleanup":
				if err := session.RequestPublisherDrain(t.Context(), "drain"); err != nil {
					t.Fatal(err)
				}
			case "relay-drain":
				if err := registry.Drain(t.Context()); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				cancel()
			}
			if err := session.Close(); err != nil {
				t.Fatal(err)
			}
			body := relayAwait(t, disconnected)
			if body.Unexpected == nil || *body.Unexpected != (mode == "loss") {
				t.Fatal("disconnect confused planned cleanup with transport loss", body.Unexpected)
			}
			err = relayAwait(t, done)
			if mode == "failed-cleanup" && !errors.Is(err, cleanupErr) {
				t.Fatal("intentional drain lost its independent cleanup failure", err)
			}
		})
	}
}
