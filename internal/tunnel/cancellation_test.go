package tunnel

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestSetupCancellationInterruptsRead(t *testing.T) {
	for _, handshake := range []bool{true, false} {
		name := "stream_ack"
		if handshake {
			name = "hello_ack"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var result <-chan error
				if handshake {
					client, server := newMemoryPair(t)
					result = tunnelWorker(t, func() { _ = client.Close() }, func() error {
						_, err := Dial(ctx, client, publisherHello())
						return err
					})
					stream, err := server.AcceptStream(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := tunnelv1.ReadControl(stream); err != nil {
						t.Fatal(err)
					}
				} else {
					client, server := newAuthenticatedPair(t)
					result = tunnelWorker(t, func() { _ = client.Close() }, func() error {
						_, err := client.OpenVisitorStream(ctx, visitorStreamHeader())
						return err
					})
					if _, err := server.AcceptVisitorStream(ctx); err != nil {
						t.Fatal(err)
					}
				}
				synctest.Wait()
				cancel()
				synctest.Wait()
				select {
				case err := <-result:
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("setup cancellation: %v", err)
					}
				default:
					t.Fatal("canceled setup is still waiting for its deadline")
				}
			})
		})
	}
}

type closeAfterTransportStream struct {
	muxsession.Stream
	done <-chan struct{}
}

func (s closeAfterTransportStream) Close() error {
	<-s.done // Models a FIN enqueue blocked behind the transport writer.
	return s.Stream.Close()
}

func TestSessionCloseReleasesBlockedControlCleanup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, _ := newAuthenticatedPair(t)
		client.control = closeAfterTransportStream{Stream: client.control, done: client.transport.Done()}
		result := tunnelWorker(t, func() { _ = client.transport.Close() }, client.Close)
		synctest.Wait()
		select {
		case err := <-result:
			if err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatal("session close waits for control FIN before stopping transport")
		}
	})
}

func TestCanceledStreamKeepsSessionUsable(t *testing.T) {
	client, server := newAuthenticatedPair(t)
	ctx, cancel := context.WithCancel(t.Context())
	result := tunnelWorker(t, cancel, func() error {
		_, err := client.OpenVisitorStream(ctx, visitorStreamHeader())
		return err
	})
	if _, err := server.AcceptVisitorStream(tunnelContext(t)); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := await(t, result); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	result = tunnelWorker(t, func() { _ = server.Close() }, func() error {
		incoming, err := server.AcceptVisitorStream(tunnelContext(t))
		if err != nil {
			return err
		}
		return incoming.Accept()
	})
	stream, err := client.OpenVisitorStream(tunnelContext(t), visitorStreamHeader())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if err := await(t, result); err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.Done():
		t.Fatal("request cancellation closed the shared session")
	default:
	}
	_ = stream.SetDeadline(time.Now())
}
