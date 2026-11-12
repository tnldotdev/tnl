package publisher

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestQUICDefaultRunReleasesUDPBeforeFallbackAndReadiness(t *testing.T) {
	control, _, _ := newCertificateTransactionTest(t)
	config := startCertificateTLSYamuxHarness(t, control)
	config.Logf = t.Logf
	config.TransportTLS = config.TCPConnector.(muxsession.TLSYamuxConnector).TLSConfig
	config.QUICConnector = nil // exercise Run's default, not an injected owner.
	var seen [publisherConnectionCount]chan struct{}
	var sources [publisherConnectionCount]net.Addr
	for slot, assignment := range control.setup.PublisherConnections {
		packet, err := net.ListenPacket("udp", assignment.RelayAddress)
		if err != nil {
			t.Fatal(err)
		}
		seen[slot] = make(chan struct{})
		done := make(chan struct{})
		t.Cleanup(func() { _ = packet.Close(); awaitPublisherTest(t, done) })
		go func() {
			defer close(done)
			_, source, err := packet.ReadFrom(make([]byte, 1500))
			if err == nil {
				sources[slot] = source
			}
			close(seen[slot])
		}()
	}
	fallbackChecked := make(chan struct{})
	tcp := config.TCPConnector
	config.TCPConnector = muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
		slot := 0
		if endpoint.Address == control.setup.PublisherConnections[1].RelayAddress {
			slot = 1
		}
		// require a real QUIC packet before allowing TCP to win. hold the second
		// fallback until the first slot's abandoned socket has been checked.
		select {
		case <-seen[slot]:
		case <-ctx.Done():
			return nil, context.Cause(ctx)
		}
		if slot == 1 {
			select {
			case <-fallbackChecked:
			case <-ctx.Done():
				return nil, context.Cause(ctx)
			}
		}
		return tcp.Connect(ctx, endpoint)
	})
	checkReleased := func(slot int) error {
		if sources[slot] == nil {
			return fmt.Errorf("slot %d never sent a QUIC packet", slot)
		}
		_, port, err := net.SplitHostPort(sources[slot].String())
		if err != nil {
			return err
		}
		// rebinding immediately proves the physical socket is closed. no wait,
		// polling, or run shutdown may release an abandoned socket for this check.
		packet, err := net.ListenPacket("udp", net.JoinHostPort("", port))
		if err != nil {
			return fmt.Errorf("slot %d retained an abandoned QUIC socket: %w", slot, err)
		}
		return packet.Close()
	}
	ready := make(chan struct{})
	config.Observe = func(event Event) error {
		switch event.Type {
		case EventTransportFallback:
			if err := checkReleased(0); err != nil {
				return err
			}
			close(fallbackChecked)
		case EventReady:
			for slot := range publisherConnectionCount {
				if err := checkReleased(slot); err != nil {
					return err
				}
			}
			close(ready)
		}
		return nil
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	var runErr error
	go func() { runErr = Run(ctx, config); close(done) }()
	t.Cleanup(func() { cancel(); awaitPublisherTest(t, done) })
	select {
	case <-ready:
	case <-done:
		t.Fatal("default publisher stopped before checking fallback and readiness", runErr)
	case <-time.After(5 * time.Second):
		t.Fatal("default publisher did not become ready")
	}
}

type publisherQUICCloseFailure struct {
	muxsession.Session
	err    error
	local  net.Addr
	closed chan struct{}
	closes atomic.Int32
}

func (s *publisherQUICCloseFailure) Close() error {
	err := errors.Join(s.Session.Close(), s.err)
	if s.closes.Add(1) == 1 {
		close(s.closed)
	}
	return err
}

func TestQUICWinnerCleanupSurvivesStaleAssignmentAndRunStop(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(fmt.Sprintf("stale=%t", stale), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			certificate := publicURLTestCertificate(t, "relay.example")
			listener, err := muxsession.ListenQUIC("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{certificate}}, muxsession.QUICConfig{})
			if err != nil {
				t.Fatal(err)
			}
			accepted, joined := make(chan error, 1), make(chan struct{})
			t.Cleanup(func() { cancel(); _ = listener.Close(); awaitPublisherTest(t, joined) })
			go func() {
				defer close(joined)
				transport, err := listener.Accept(ctx)
				if err != nil {
					accepted <- err
					return
				}
				defer transport.Close()
				session, _, err := tunnel.Accept(ctx, transport, func(context.Context, tunnelv1.Message) error { return nil })
				accepted <- err
				if err == nil {
					<-session.Done()
				}
			}()
			closeErr := errors.New("owned QUIC winner cleanup failed")
			clients := make(chan *publisherQUICCloseFailure, 1)
			owned := muxsession.OwnedQUICConnector{TLSConfig: &tls.Config{RootCAs: rootsForCertificate(t, certificate)}}
			var manager *publisherConnectionManager
			quic := muxsession.ConnectorFunc(func(ctx context.Context, endpoint muxsession.Endpoint) (muxsession.Session, error) {
				native, err := owned.Connect(ctx, endpoint)
				if err != nil {
					return nil, err
				}
				client := &publisherQUICCloseFailure{Session: native, err: closeErr, local: native.(muxsession.AcceptedPeer).LocalAddr(), closed: make(chan struct{})}
				clients <- client
				if stale {
					manager.mu.Lock()
					manager.assignments[0] = &publisherConnectionAssignment{assignment: manager.assignments[0].assignment}
					manager.mu.Unlock()
				}
				return client, nil
			})
			route := certificateTestPublicURL(t, "route.example", publicURLCertificateTestPlan())
			manager, err = newPublisherConnectionManager(ctx, publisherConnectionManagerConfig{
				QUICConnector: quic, TCPConnector: muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
					return nil, errors.New("QUIC winner must not start TCP")
				}), FallbackDelay: time.Hour, ReconnectDelay: time.Second,
			}, route, "publish_run_1", "public_url_1", 1)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = manager.Close() })
			assignment := publisherTestAssignment(0, time.Now().Add(time.Minute))
			assignment.RelayAddress = listener.Addr().String()
			manager.assignments[0] = &publisherConnectionAssignment{assignment: assignment}
			if err := manager.paths.Set(0, "initial"); err != nil {
				t.Fatal(err)
			}
			client := awaitPublisherTest(t, clients)
			if err := awaitPublisherTest(t, accepted); err != nil {
				t.Fatal(err)
			}
			if stale {
				awaitPublisherTest(t, client.closed)
				err = manager.Close()
				if !errors.Is(err, tunnel.ErrAwaitAssignment) {
					t.Fatal("stale winner lost its assignment fence", err)
				}
			} else {
				if err := manager.WaitReady(ctx, 1); err != nil {
					t.Fatal(err)
				}
				sessionCtx, cancelSession := context.WithCancelCause(ctx)
				expired := make(chan struct{})
				close(expired)
				cleanup := publishRunCleanup{parentCtx: ctx, sessionCtx: sessionCtx, cancelSession: cancelSession, cancelTransports: cancel, connections: manager, expirationDone: expired}
				err = cleanup.finish(nil)
			}
			if !errors.Is(err, closeErr) || client.closes.Load() != 1 {
				t.Fatal("public owner lost its QUIC winner cleanup error or closed twice", err, client.closes.Load())
			}
			if err := manager.Close(); !errors.Is(err, closeErr) || client.closes.Load() != 1 {
				t.Fatal("repeated manager close lost its cached cleanup failure", err)
			}
			packet, err := net.ListenPacket("udp", client.local.String())
			if err != nil {
				t.Fatal("public owner returned before releasing the QUIC winner socket", err)
			}
			_ = packet.Close()
		})
	}
}

func TestQUICFailedConnectCleanupSurvivesCanceledManagerClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cleanupErr, cause := errors.New("failed owned QUIC dial cleanup failed"), errors.New("publisher owner canceled")
		ctx, cancel := context.WithCancelCause(t.Context())
		defer cancel(cause)
		entered := make(chan struct{})
		quic := muxsession.ConnectorFunc(func(ctx context.Context, _ muxsession.Endpoint) (muxsession.Session, error) {
			close(entered)
			<-ctx.Done()
			return nil, errors.Join(ctx.Err(), context.Cause(ctx), &muxsession.QUICTransportCloseError{Err: cleanupErr})
		})
		route := certificateTestPublicURL(t, "route.example", publicURLCertificateTestPlan())
		manager, err := newPublisherConnectionManager(ctx, publisherConnectionManagerConfig{
			QUICConnector: quic, TCPConnector: quic, FallbackDelay: time.Hour, ReconnectDelay: time.Second,
		}, route, "publish_run_1", "public_url_1", 1)
		if err != nil {
			t.Fatal(err)
		}
		manager.assignments[0] = &publisherConnectionAssignment{assignment: publisherTestAssignment(0, time.Now().Add(time.Minute))}
		if err := manager.paths.Set(0, "initial"); err != nil {
			t.Fatal(err)
		}
		<-entered
		cancel(cause)
		if err := manager.Close(); !errors.Is(err, cleanupErr) || !errors.Is(err, cause) || !errors.Is(err, context.Canceled) {
			t.Fatal("canceled manager lost failed-Connect cleanup facts", err)
		}
	})
}
