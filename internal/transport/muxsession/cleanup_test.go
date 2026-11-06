package muxsession

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestYamuxWriterFailureDoesNotWaitForTLSCloseNotify(t *testing.T) {
	for _, failure := range []string{"deadline setup", "write timeout"} {
		t.Run(failure, func(t *testing.T) { testYamuxWriterFailure(t, failure == "write timeout") })
	}
}

func testYamuxWriterFailure(t *testing.T, timeout bool) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		serverTLS, clientTLS := testTLSConfigs(t)
		clientTLS.ServerName = "relay.test"
		local, peer := net.Pipe()
		defer peer.Close()
		failure := errors.New("write deadline unavailable")
		network := &failYamuxWriteDeadlineConn{Conn: local, failure: failure}
		secure, remote := tls.Client(network, clientTLS), tls.Server(peer, serverTLS)
		handshake := make(chan error, 1)
		go func() { handshake <- remote.HandshakeContext(t.Context()) }()
		if err := secure.HandshakeContext(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := <-handshake; err != nil {
			t.Fatal(err)
		}
		// fail the yamux writer at deadline setup or while writing TLS records
		// to a peer that no longer reads. sendMsg waits for shutdown after the
		// writer exits, so TLS shutdown must close the raw socket immediately.
		network.fail.Store(!timeout)
		session, err := newYamuxSession(secure, true, 4096)
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		if timeout {
			time.Sleep(yamuxConfig(4096).ConnectionWriteTimeout)
		}
		synctest.Wait()
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		started := time.Now()
		// yamux can enqueue another SYN after its writer exits because its send
		// queue is buffered. the next attempt that observes sendDone must not
		// wait for a TLS alert; the session owns any enqueued test streams.
		for err == nil {
			_, err = session.OpenStream(ctx)
		}
		if timeout {
			var timedOut net.Error
			if !errors.As(err, &timedOut) || !timedOut.Timeout() {
				t.Fatal("lost writer timeout", err)
			}
		} else if !errors.Is(err, failure) {
			t.Fatal("lost writer failure", err)
		}
		if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
			t.Fatalf("opening waited %s for TLS close-notify after writer failure", elapsed)
		}
		if !errors.Is(session.Err(), err) {
			t.Fatal("session lost writer failure", session.Err())
		}
	})
}

type failYamuxWriteDeadlineConn struct {
	net.Conn
	fail    atomic.Bool
	failure error
}

func (c *failYamuxWriteDeadlineConn) SetWriteDeadline(deadline time.Time) error {
	if c.fail.Swap(false) {
		return c.failure
	}
	return c.Conn.SetWriteDeadline(deadline)
}

func TestYamuxCleanupWithBlockedWriter(t *testing.T) {
	for _, operation := range []string{"close", "half_close", "reset"} {
		t.Run(operation, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				local, peer := net.Pipe()
				defer peer.Close()
				session, err := newYamuxSession(local, true, 4096)
				if err != nil {
					t.Fatal(err)
				}
				defer session.Close()
				stream, err := session.OpenStream(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				// fill the library's send queue while the peer never reads. the
				// deadline makes the final open the explicit saturation boundary.
				ctx, cancel := context.WithTimeout(t.Context(), time.Millisecond)
				defer cancel()
				for {
					if _, err := session.OpenStream(ctx); err != nil {
						break
					}
				}
				started := time.Now()
				var cleanupErr error
				switch operation {
				case "close":
					cleanupErr = stream.Close()
				case "half_close":
					cleanupErr = stream.CloseWrite()
				case "reset":
					cleanupErr = stream.Reset(1)
				}
				if elapsed := time.Since(started); elapsed > 2*time.Second {
					t.Fatalf("%s waited %s for failed writer: %v", operation, elapsed, cleanupErr)
				}
				if cleanupErr == nil {
					t.Fatal("blocked cleanup lost its error")
				}
				select {
				case <-session.Done():
				default:
					t.Fatal("unusable writer retained by session")
				}
				if !errors.Is(session.Err(), errStreamCleanupBlocked) {
					t.Fatalf("lost stream-cleanup shutdown reason: %v", session.Err())
				}
			})
		})
	}
}

func TestYamuxErrRetainsPeerCloseReason(t *testing.T) {
	local, peer := net.Pipe()
	session, err := newYamuxSession(local, true, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-session.Done():
	case <-time.After(time.Second):
		t.Fatal("peer close did not stop yamux session")
	}
	// the send loop can observe the peer close before the receive loop does.
	if err := session.Err(); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("lost peer close reason: %v", err)
	}
}
