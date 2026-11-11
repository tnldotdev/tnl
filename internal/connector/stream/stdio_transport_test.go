package stream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	yamux "github.com/libp2p/go-yamux/v5"
	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/testutil/transporttest"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
)

func stdioTransportSessions(t *testing.T, transport string) (muxsession.Session, muxsession.Session) {
	t.Helper()
	root, certificate := providerCertificate(t)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(root)
	serverTLS := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	clientTLS := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	var endpoint muxsession.Endpoint
	accepted := make(chan muxsession.Session, 1)
	failed := make(chan error, 1)
	var workers sync.WaitGroup
	if transport == "quic" {
		listener, err := muxsession.ListenQUIC("127.0.0.1:0", serverTLS, muxsession.QUICConfig{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close(); cancel(); workers.Wait() })
		endpoint = muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "db.example"}
		workers.Go(func() {
			session, err := listener.Accept(ctx)
			if err != nil {
				failed <- err
			} else {
				accepted <- session
			}
		})
	} else {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close(); cancel(); workers.Wait() })
		endpoint = muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "db.example"}
		workers.Go(func() {
			connection, err := listener.Accept()
			if err != nil {
				failed <- err
				return
			}
			session, err := muxsession.AcceptTLSYamux(ctx, connection, serverTLS, muxsession.TLSYamuxConfig{})
			if err != nil {
				_ = connection.Close()
				failed <- err
			} else {
				accepted <- session
			}
		})
	}
	var connector muxsession.Connector = muxsession.QUICConnector{TLSConfig: clientTLS, Dialer: transporttest.QUICTransport(t)}
	if transport != "quic" {
		connector = muxsession.TLSYamuxConnector{TLSConfig: clientTLS}
	}
	client, err := connector.Connect(ctx, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	var server muxsession.Session
	select {
	case server = <-accepted:
	case err := <-failed:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

func stdioTransportPair(t *testing.T, transport string) (muxsession.Stream, muxsession.Stream) {
	t.Helper()
	client, server := stdioTransportSessions(t, transport)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	left, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = left.Close() })
	if _, err := left.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	right, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = right.Close() })
	if _, err := io.ReadFull(right, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	return left, right
}

type stdioResetReadBarrier struct {
	muxsession.Stream
	readDone <-chan struct{}
}

func (s stdioResetReadBarrier) Reset(code uint32) error {
	err := s.Stream.Reset(code)
	<-s.readDone
	return err
}

type stdioReadCompleted struct {
	net.Conn
	done func()
}

func (c stdioReadCompleted) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.done()
	return n, err
}

func TestStdioResetJoinsReaderBeforeResetReturns(t *testing.T) {
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			raw, _ := stdioTransportPair(t, transport)
			local, peer := net.Pipe()
			defer peer.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			readDone := make(chan struct{})
			release := sync.OnceFunc(func() { close(readDone) })
			defer release()
			o := newStdioOperation(ctx, local)
			selected, err := o.bind(stdioResetReadBarrier{Stream: raw, readDone: readDone})
			if err != nil {
				t.Fatal(err)
			}
			if err := o.activate(selected); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				// the reset wakes the remote copy, whose failure closes stdin.
				// hold Reset until the stdin result has been classified.
				_, err := streamcopy.Copy(stdioReadCompleted{Conn: o.local, done: release}, selected)
				o.complete()
				done <- o.finish(err)
			}()
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal("ordinary cancellation leaked the reader's close error", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("reset and copy workers did not join")
			}
		})
	}
}

func TestStdioAbortRealTransportOppositeResetOrders(t *testing.T) {
	for _, transport := range []string{"quic", "tls-tcp"} {
		for _, order := range []string{"remote first", "caller first", "unpublished local zero", "local nonzero first"} {
			t.Run(transport+"/"+order, func(t *testing.T) {
				raw, remote := stdioTransportPair(t, transport)
				local, peer := net.Pipe()
				defer peer.Close()
				ctx, cancel := context.WithCancelCause(t.Context())
				defer cancel(nil)
				o := newStdioOperation(ctx, local)
				selected, err := o.bind(raw)
				if err != nil {
					t.Fatal(err)
				}
				if err := o.activate(selected); err != nil {
					t.Fatal(err)
				}
				var copied error
				switch order {
				case "remote first":
					if err := remote.Reset(7); err != nil {
						t.Fatal(err)
					}
					_, copied = selected.Read(make([]byte, 1))
				case "unpublished local zero":
					if err := selected.Reset(0); err != nil {
						t.Fatal(err)
					}
				case "local nonzero first":
					if err := selected.Reset(7); err != nil {
						t.Fatal(err)
					}
				}
				o.stop(context.Canceled, true)
				cancel(context.Canceled)
				if order != "remote first" {
					if err := remote.Reset(7); err != nil {
						t.Fatal(err)
					}
					_, copied = selected.Read(make([]byte, 1))
				}
				cleanup := selected.Close()
				o.complete()
				result := o.finish(errors.Join(copied, cleanup))
				if order == "caller first" {
					var evidence *stdioAbortError
					if result != nil || !errors.As(copied, &evidence) || evidence.owner != o || evidence.stream != selected {
						t.Fatal("selected stream did not carry exact abort evidence", result, copied)
					}
				} else if result == nil || !errors.Is(result, copied) {
					t.Fatal("ordinary cancellation hid a preceding or unowned reset", result, copied)
				}
				if order == "remote first" {
					var q *quic.StreamError
					var y *yamux.StreamError
					if errors.As(result, &q) {
						if !q.Remote || q.ErrorCode != 7 {
							t.Fatal("QUIC reset origin changed")
						}
					} else if errors.As(result, &y) {
						if !y.Remote || y.ErrorCode != 7 {
							t.Fatal("yamux reset origin changed")
						}
					} else {
						t.Fatal("typed remote reset was lost", result)
					}
				}
			})
		}
	}
}
