package service

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/testutil/transporttest"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// this relay fixture accepts actual verified QUIC/TLS and publisher hellos.
// control remains the existing in-memory lifecycle fake, not PostgreSQL.
type observationRelay struct {
	accepted [2]chan *tunnel.Session
	closed   [2]chan struct{}
	before   func(tunnelv1.ServicePublisherConnectionRef)
	stop     func()
}

func newObservationRelay(t *testing.T, cfg *RunConfig, control *lifecycleControl, transport tunnel.Transport, before func(tunnelv1.ServicePublisherConnectionRef)) *observationRelay {
	t.Helper()
	serverTLS, roots := privateTransportTLS(t)
	listener, packet, err := transporttest.ListenTCPUDP()
	if err != nil {
		t.Fatal(err)
	}
	udp, err := muxsession.ListenQUICPacket(packet, serverTLS, muxsession.QUICConfig{Config: &quic.Config{EnableDatagrams: true}})
	if err != nil {
		_ = listener.Close()
		_ = packet.Close()
		t.Fatal(err)
	}
	for slot := range 2 {
		control.setup.PublisherConnections[slot].RelayAddress = listener.Addr().String()
		control.setup.PublisherConnections[slot].TlsServerName = "relay.test"
	}
	cfg.TransportTLS, cfg.HeartbeatInterval = roots, 50*time.Millisecond
	cfg.Connectivity.DisableDirect = true
	disabled := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		return nil, net.ErrClosed
	})
	if transport == tunnel.TransportQUIC {
		cfg.RelayTCP = disabled
	} else {
		cfg.RelayQUIC = disabled
	}
	r := &observationRelay{before: before}
	for slot := range 2 {
		r.accepted[slot], r.closed[slot] = make(chan *tunnel.Session, 1), make(chan struct{})
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(t.Context()))
	var acceptors, workers sync.WaitGroup
	serve := func(outer muxsession.Session) {
		defer outer.Close()
		stop := context.AfterFunc(ctx, func() { _ = outer.Close() })
		defer stop()
		session, hello, err := tunnel.Accept(ctx, outer, func(_ context.Context, hello tunnelv1.Message) error {
			ref := hello.ServiceConnection
			if ref == nil || ref.ConnectionSlot > 1 {
				return ErrPrivateStream
			}
			assignment := control.setup.PublisherConnections[ref.ConnectionSlot]
			expected := tunnelv1.ServicePublisherConnectionRef{ServiceID: control.prep.ServiceId, ServiceRunID: control.prep.ServiceRunId,
				RunNumber: uint64(control.prep.RunNumber), PublisherConnectionID: assignment.PublisherConnectionId,
				ConnectionSlot: uint8(assignment.ConnectionSlot), ConnectionAssignmentRevision: uint64(assignment.ConnectionAssignmentRevision), RelayServiceID: assignment.RelayServiceId}
			if *ref != expected || hello.Credential != assignment.PublisherConnectionCredential {
				return ErrPrivateStream
			}
			if r.before != nil {
				r.before(*ref)
			}
			return nil
		})
		if err != nil {
			return
		}
		defer session.Close()
		slot := hello.ServiceConnection.ConnectionSlot
		r.accepted[slot] <- session
		defer close(r.closed[slot])
		drained := make(chan struct{})
		go func() {
			defer close(drained)
			_ = session.HandlePublisherDrain(ctx, func(context.Context) error { return nil })
		}()
		_ = session.ServeServiceCapacity(ctx)
		_ = session.Close()
		<-drained
	}
	acceptors.Go(func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Go(func() {
				defer conn.Close()
				outer, err := muxsession.AcceptTLSYamux(ctx, conn, serverTLS, muxsession.TLSYamuxConfig{})
				if err == nil {
					serve(outer)
				}
			})
		}
	})
	acceptors.Go(func() {
		for {
			outer, err := udp.Accept(ctx)
			if err != nil {
				return
			}
			workers.Go(func() { serve(outer) })
		}
	})
	r.stop = sync.OnceFunc(func() {
		cancel()
		_ = listener.Close()
		_ = udp.Close()
		_ = packet.Close()
		acceptors.Wait()
		workers.Wait()
	})
	t.Cleanup(r.stop)
	return r
}

func TestServiceFallbackObservationRestorationStaleAcceptedTLSIsNeverConnected(t *testing.T) {
	cfg, control := lifecycleFixture(t)
	bounds := make(chan *Bound, 1)
	relay := newObservationRelay(t, &cfg, control, tunnel.TransportTLSTCP, func(tunnelv1.ServicePublisherConnectionRef) {
		bound := <-bounds
		bound.Invalidate()
	})
	attempted := make(chan error, 1)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cfg.Connect = func(ctx context.Context, bound *Bound, slot uint8, options ConnectOptions) (SlotSession, error) {
		if slot == 1 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		bounds <- bound
		claimed, err := bound.ConnectSlot(ctx, slot, options)
		attempted <- err
		return claimed, err
	}
	var statuses []RunStatus
	cfg.ObserveReadiness = func(status RunStatus) { statuses = append(statuses, status) }
	ready := false
	cfg.Ready = func() error { ready = true; return nil }
	result := make(chan error, 1)
	go func() { result <- Publish(ctx, cfg) }()
	if err := claimedAwait(t, attempted); !errors.Is(err, ErrPrivateStream) {
		t.Fatal("stale accepted TLS did not return its exact stale-state cause", err)
	}
	cancel()
	_ = claimedAwait(t, result)
	claimedAwait(t, relay.closed[0])
	if ready {
		t.Fatal("stale accepted TLS notified readiness")
	}
	for _, status := range statuses {
		if status.Ready || status.Connected[0] || status.Transports[0] != "" {
			t.Fatal("stale accepted TLS became a connected fallback observation", status)
		}
	}
}
