package streamcopy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	yamux "github.com/libp2p/go-yamux/v5"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

func copyYamuxPair(t *testing.T, resetOnClose bool) (muxsession.Session, muxsession.Session) {
	t.Helper()
	ca, certificate := testutil.TLSCertificate(t, []string{"relay.test"}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("fixture trust is invalid")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(func() { cancel(); _ = listener.Close() })
	type accepted struct {
		session muxsession.Session
		err     error
	}
	result := make(chan accepted, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		connection, err := listener.Accept()
		if err != nil {
			result <- accepted{err: err}
			return
		}
		closed := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { _ = connection.Close(); close(closed) })
		session, err := muxsession.AcceptTLSYamux(ctx, connection, &tls.Config{Certificates: []tls.Certificate{certificate}}, muxsession.TLSYamuxConfig{})
		if !stop() {
			<-closed
		}
		if err != nil {
			_ = connection.Close()
		}
		result <- accepted{session: session, err: err}
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		select {
		case <-joined:
		case <-time.After(5 * time.Second):
			t.Error("TLS/yamux fixture did not join")
		}
	})
	dialer := new(net.Dialer)
	if resetOnClose {
		dialer.Control = func(_, _ string, raw syscall.RawConn) error {
			var socketErr error
			controlErr := raw.Control(func(fd uintptr) {
				socketErr = syscall.SetsockoptLinger(int(fd), syscall.SOL_SOCKET, syscall.SO_LINGER, &syscall.Linger{Onoff: 1})
			})
			return errors.Join(controlErr, socketErr)
		}
	}
	client, err := (muxsession.TLSYamuxConnector{TLSConfig: &tls.Config{RootCAs: roots}, Config: muxsession.TLSYamuxConfig{Dialer: dialer}}).Connect(ctx, muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "relay.test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server := <-result
	if server.err != nil {
		t.Fatal(server.err)
	}
	t.Cleanup(func() { _ = server.session.Close() })
	return client, server.session
}

func TestCopyRealYamuxResetAndSessionEOFStopIdleDirection(t *testing.T) {
	for _, name := range []string{"stream_reset", "session_close", "session_reset"} {
		t.Run(name, func(t *testing.T) {
			client, server := copyYamuxPair(t, name == "session_reset")
			sessionLoss := name != "stream_reset"
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			outbound, err := client.OpenStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			inbound, err := server.AcceptStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			right, _ := tcpPair(t)
			result := startCopy(t, inbound, right, nil, nil)
			if sessionLoss {
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
			} else if err := outbound.Reset(17); err != nil {
				t.Fatal(err)
			}
			got := copyResult(t, result)
			if !errors.Is(got.err, yamux.ErrStreamReset) {
				t.Fatalf("real reset lost its cause: %v", got.err)
			}
			if sessionLoss {
				// an abrupt TCP close can produce EOF or a reset. preserve the
				// session's exact cause instead of assuming which one wins.
				cause := server.Err()
				if cause == nil || !errors.Is(got.err, cause) {
					t.Fatalf("session failure lost its cause: %v; want %v", got.err, cause)
				}
				if name == "session_reset" && !errors.Is(cause, syscall.ECONNRESET) {
					t.Fatalf("abortive TCP close did not produce a reset: %v", cause)
				}
				return
			}
			var reset *yamux.StreamError
			if !errors.As(got.err, &reset) || !reset.Remote || reset.ErrorCode != 17 {
				t.Fatalf("real stream reset lost typed remote/code evidence: %v", got.err)
			}
			if client.Err() != nil || server.Err() != nil {
				t.Fatal("failed stream closed its borrowed session")
			}
			sibling, err := client.OpenStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer sibling.Close()
			peer, err := server.AcceptStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			if _, err := sibling.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			var ping [4]byte
			if _, err := io.ReadFull(peer, ping[:]); err != nil || string(ping[:]) != "ping" {
				t.Fatalf("sibling request=%q error=%v", ping, err)
			}
		})
	}
}
