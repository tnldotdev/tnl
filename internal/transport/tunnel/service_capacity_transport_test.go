package tunnel

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func serveTestCapacity(t *testing.T, session *Session) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- session.ServeServiceCapacity(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := await(t, done); err != nil {
			t.Error("capacity reader did not join", err)
		}
	})
}

func capacityVisitorPair(t *testing.T, sender, receiver *Session, header tunnelv1.ServiceForwardingHeader) (muxsession.Stream, muxsession.Stream) {
	t.Helper()
	ctx := tunnelContext(t)
	accepted := tunnelWorker(t, func() { _ = receiver.Close() }, func() *IncomingServiceForwardingStream {
		incoming, err := receiver.AcceptServiceForwardingStream(ctx)
		if err != nil {
			t.Error("accept service stream", err)
			return nil
		}
		if err := incoming.Accept(); err != nil {
			t.Error("accept service stream", err)
			return nil
		}
		return incoming
	})
	stream, err := sender.OpenServiceForwardingStream(ctx, header)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	peer := await(t, accepted)
	if peer == nil {
		t.Fatal("no accepted service stream")
	}
	t.Cleanup(func() { _ = peer.Stream().Close() })
	return stream, peer.Stream()
}

func TestServiceCapacityRealTransportsCarryRepliesThroughRelay(t *testing.T) {
	for _, transport := range []string{"quic", "wss"} {
		t.Run(transport, func(t *testing.T) {
			header := maximumServiceHeader("relay-a")
			ref := ServiceForwardingRef(header)
			ingress, relayIngress := realTunnelPairWithHello(t, transport, ingressBoundsHello())
			publisher, relayPublisher := realTunnelPairWithHello(t, transport, tunnelv1.Message{
				Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Publisher,
				Credential: "publisher-credential", ServiceConnection: &ref,
			})
			visitor, relayVisitor := capacityVisitorPair(t, ingress, relayIngress, header)
			toPublisher, publisherVisitor := capacityVisitorPair(t, relayPublisher, publisher, header)
			serveTestCapacity(t, ingress)
			peerReader := blockedPeerIntroduction{started: make(chan struct{})}
			dispatcher, err := NewServiceStreamDispatcher(t.Context(), relayPublisher, peerReader)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := dispatcher.Close(); err != nil {
					t.Error("shared service reader did not join", err)
				}
			})
			var decisions atomic.Int32
			releaseIngress, err := ingress.RegisterServiceCapacity(t.Context(), header, func(context.Context) error {
				decisions.Add(1)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer releaseIngress()
			releaseRelay, err := relayPublisher.RegisterServiceCapacity(t.Context(), header, func(ctx context.Context) error {
				return relayIngress.RequestServiceCapacity(ctx, header)
			})
			if err != nil {
				t.Fatal(err)
			}
			defer releaseRelay()
			ctx := tunnelContext(t)
			results := make(chan error, 8)
			var callers sync.WaitGroup
			for range 8 {
				callers.Go(func() { results <- publisher.RequestServiceCapacity(ctx, header) })
			}
			callers.Wait()
			for range 8 {
				if err := <-results; err != nil {
					t.Fatal("capacity reply did not cross both sessions", err)
				}
			}
			if decisions.Load() != 1 {
				t.Fatal("duplicate replies consumed capacity again", decisions.Load())
			}
			packet, err := publisher.transport.OpenStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			if _, err := packet.Write([]byte{tunnelv1.Version}); err != nil {
				t.Fatal(err)
			}
			await(t, peerReader.started)
			for _, pair := range [][2]muxsession.Stream{{visitor, relayVisitor}, {toPublisher, publisherVisitor}} {
				written := tunnelWorker(t, func() { _ = pair[0].Close() }, func() error {
					_, err := io.WriteString(pair[0], "unchanged visitor bytes")
					return err
				})
				payload := make([]byte, len("unchanged visitor bytes"))
				if _, err := io.ReadFull(pair[1], payload); err != nil || string(payload) != "unchanged visitor bytes" {
					t.Fatal("capacity replies changed the visitor stream", err)
				}
				if err := await(t, written); err != nil {
					t.Fatal(err)
				}
			}
			changed := header
			changed.SourceIP = "192.0.2.31"
			if err := publisher.RequestServiceCapacity(ctx, changed); err == nil {
				t.Fatal("relay accepted another stream's source")
			}
			releaseIngress()
			releaseRelay()
			if err := publisher.RequestServiceCapacity(ctx, header); err == nil {
				t.Fatal("a released stream still received a capacity reply")
			}
			if ingress.Err() != nil || relayIngress.Err() != nil || publisher.Err() != nil || relayPublisher.Err() != nil {
				t.Fatal("a rejected capacity request closed an authenticated session")
			}
		})
	}
}

func TestServiceCapacityRealTransportsKeepCapacityRejection(t *testing.T) {
	for _, transport := range []string{"quic", "wss"} {
		t.Run(transport, func(t *testing.T) {
			requester, ingress := realTunnelPairWithHello(t, transport, ingressBoundsHello())
			serveTestCapacity(t, ingress)
			header := maximumServiceHeader("relay-a")
			release, err := ingress.RegisterServiceCapacity(t.Context(), header, func(context.Context) error {
				return &ProtocolError{Code: tunnelv1.CapacityExceeded}
			})
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			for range 2 {
				err := requester.RequestServiceCapacity(tunnelContext(t), header)
				var rejected *ProtocolError
				if !errors.As(err, &rejected) || rejected.Code != tunnelv1.CapacityExceeded {
					t.Fatal("transport lost capacity rejection", err)
				}
			}
		})
	}
}
