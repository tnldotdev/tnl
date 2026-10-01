package tunnel

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestAcceptSetupDeadlineBoundsControlStreamAndAuthentication(t *testing.T) {
	t.Run("control_stream", func(t *testing.T) {
		captured := make(chan time.Time, 1)
		failure := errors.New("accept stopped")
		started := time.Now()
		_, _, err := Accept(t.Context(), acceptContextSession{captured: captured, failure: failure}, func(context.Context, tunnelv1.Message) error {
			return nil
		})
		if !errors.Is(err, failure) {
			t.Fatalf("accept = %v", err)
		}
		assertSetupDeadline(t, <-captured, started)
	})

	t.Run("authentication", func(t *testing.T) {
		client, server := newMemoryPair(t)
		captured := make(chan time.Time, 1)
		serverResult := tunnelWorker(t, func() { _ = server.Close() }, func() error {
			_, _, err := Accept(t.Context(), server, func(ctx context.Context, _ tunnelv1.Message) error {
				deadline, _ := ctx.Deadline()
				captured <- deadline
				return &ProtocolError{Code: tunnelv1.Unauthenticated}
			})
			return err
		})
		started := time.Now()
		if _, err := Dial(t.Context(), client, publisherHello()); err == nil {
			t.Fatal("dial accepted rejected authentication")
		}
		assertSetupDeadline(t, await(t, captured), started)
		if err := await(t, serverResult); err == nil {
			t.Fatal("accept returned no authentication error")
		}
	})
}

type acceptContextSession struct {
	captured chan<- time.Time
	failure  error
}

func (s acceptContextSession) OpenStream(context.Context) (muxsession.Stream, error) {
	return nil, errors.ErrUnsupported
}

func (s acceptContextSession) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	deadline, _ := ctx.Deadline()
	s.captured <- deadline
	return nil, s.failure
}

func (acceptContextSession) Close() error          { return nil }
func (acceptContextSession) Done() <-chan struct{} { return nil }
func (acceptContextSession) Err() error            { return nil }

func assertSetupDeadline(t *testing.T, deadline, started time.Time) {
	t.Helper()
	if !deadline.After(started) || deadline.After(started.Add(handshakeTimeout+time.Second)) {
		t.Fatalf("setup deadline = %s, want within %s", deadline, handshakeTimeout)
	}
}

type deadlineRecorder struct {
	net.Conn
	mu        sync.Mutex
	deadlines []time.Time
}

func (c *deadlineRecorder) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, deadline)
	c.mu.Unlock()
	return c.Conn.SetDeadline(deadline)
}

func TestSetupDeadlineClearsOnlyAfterSuccess(t *testing.T) {
	for _, success := range []bool{false, true} {
		t.Run(map[bool]string{false: "failure", true: "success"}[success], func(t *testing.T) {
			local, remote := net.Pipe()
			t.Cleanup(func() { _ = local.Close(); _ = remote.Close() })
			connection := &deadlineRecorder{Conn: local}
			finish, err := setupDeadline(t.Context(), connection)
			if err != nil {
				t.Fatal(err)
			}
			if err := finish(success); err != nil {
				t.Fatal(err)
			}
			connection.mu.Lock()
			defer connection.mu.Unlock()
			if got := connection.deadlines[len(connection.deadlines)-1].IsZero(); got != success {
				t.Fatalf("final deadline cleared = %t, want %t", got, success)
			}
		})
	}
}

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
	<-s.done // models a FIN enqueue blocked behind the transport writer.
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
