package tunnel

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	yamux "github.com/libp2p/go-yamux/v5"
	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func realTunnelPair(t *testing.T, transport string) (*Session, *Session) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"relay.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}
	serverTLS, clientTLS := &tls.Config{Certificates: []tls.Certificate{certificate}}, &tls.Config{RootCAs: roots}
	ctx := tunnelContext(t)
	var accept func() (muxsession.Session, error)
	var closeListener func()
	var connector muxsession.Connector
	var address string
	if transport == "quic" {
		listener, err := muxsession.ListenQUIC("127.0.0.1:0", serverTLS, muxsession.QUICConfig{})
		if err != nil {
			t.Fatal(err)
		}
		closeListener = func() { _ = listener.Close() }
		address = listener.Addr().String()
		accept = func() (muxsession.Session, error) { return listener.Accept(ctx) }
		connector = muxsession.QUICConnector{TLSConfig: clientTLS}
	} else {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		closeListener = func() { _ = listener.Close() }
		address = listener.Addr().String()
		accept = func() (muxsession.Session, error) {
			connection, err := listener.Accept()
			if err != nil {
				return nil, err
			}
			session, err := muxsession.AcceptTLSYamux(ctx, connection, serverTLS, muxsession.TLSYamuxConfig{})
			if err != nil {
				_ = connection.Close()
			}
			return session, err
		}
		connector = muxsession.TLSYamuxConnector{TLSConfig: clientTLS}
	}
	t.Cleanup(closeListener)
	type accepted struct {
		session *Session
		err     error
	}
	peer := tunnelWorker(t, closeListener, func() accepted {
		transport, err := accept()
		if err != nil {
			return accepted{err: err}
		}
		session, _, err := Accept(ctx, transport, func(context.Context, tunnelv1.Message) error { return nil })
		return accepted{session, err}
	})
	connection, err := connector.Connect(ctx, muxsession.Endpoint{Address: address, ServerName: "relay.test"})
	if err != nil {
		t.Fatal(err)
	}
	client, err := Dial(ctx, connection, publisherHello())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server := await(t, peer)
	if server.err != nil {
		t.Fatal(server.err)
	}
	t.Cleanup(func() { _ = server.session.Close() })
	return client, server.session
}

func realVisitorPair(t *testing.T, client, server *Session) (muxsession.Stream, muxsession.Stream) {
	t.Helper()
	accepted := tunnelWorker(t, func() { _ = server.Close() }, func() *IncomingVisitorStream {
		incoming, err := server.AcceptVisitorStream(tunnelContext(t))
		if err != nil {
			t.Error(err)
			return nil
		}
		if err := incoming.Accept(); err != nil {
			t.Error(err)
			return nil
		}
		return incoming
	})
	h := visitorStreamHeader()
	stream, err := client.OpenVisitorStream(tunnelContext(t), h, ReturnEvents{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	incoming := await(t, accepted)
	if incoming == nil {
		t.Fatal("missing stream")
	}
	t.Cleanup(func() { _ = incoming.Stream.Close() })
	for _, c := range []net.Conn{stream, incoming.Stream} {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	}
	return stream, incoming.Stream
}

func tunnelTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_ = listener.SetDeadline(time.Now().Add(5 * time.Second))
	a, err := net.DialTimeout("tcp4", listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	b, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	for _, c := range []net.Conn{a, b} {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	}
	return a.(*net.TCPConn), b
}

func TestPublicReturnStreamRealHalfCloseAndServerFirst(t *testing.T) {
	for _, transport := range []string{"quic", "tls_yamux"} {
		t.Run(transport, func(t *testing.T) {
			client, server := realTunnelPair(t, transport)
			stream, publisher := realVisitorPair(t, client, server)
			visitor, front := tunnelTCPPair(t)
			type copied struct {
				result streamcopy.Result
				err    error
			}
			copyDone := tunnelWorker(t, func() { _ = front.Close(); _ = stream.Close() }, func() copied { r, err := streamcopy.Copy(front, stream); return copied{r, err} })
			request, response := bytes.Repeat([]byte("request"), 12000), bytes.Repeat([]byte("response"), 11000)
			worker := tunnelWorker(t, func() { _ = publisher.Close() }, func() error {
				if _, err := publisher.Write([]byte("greeting")); err != nil {
					return err
				}
				got, err := io.ReadAll(publisher)
				if err != nil {
					return err
				}
				if !bytes.Equal(got, request) {
					return errors.New("half-close lost request bytes")
				}
				if _, err := publisher.Write(response); err != nil {
					return err
				}
				return publisher.CloseWrite()
			})
			var greeting [8]byte
			if _, err := io.ReadFull(visitor, greeting[:]); err != nil || string(greeting[:]) != "greeting" {
				t.Fatal("server-first blocked", err)
			}
			if _, err := visitor.Write(request); err != nil {
				t.Fatal(err)
			}
			if err := visitor.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(visitor)
			if err != nil || !bytes.Equal(got, response) {
				t.Fatal("response half-close lost bytes", err)
			}
			if err := await(t, worker); err != nil {
				t.Fatal(err)
			}
			result := await(t, copyDone)
			if result.err != nil || result.result != (streamcopy.Result{LeftToRight: int64(len(request)), RightToLeft: int64(len(response) + len(greeting))}) {
				t.Fatalf("copy accounting: %+v, %v", result.result, result.err)
			}
		})
	}
}

func TestPublicReturnStreamEndOwnsPostTLSDeadline(t *testing.T) {
	for _, transport := range []string{"quic", "tls_yamux"} {
		t.Run(transport, func(t *testing.T) {
			client, server := realTunnelPair(t, transport)
			stream, publisher := realVisitorPair(t, client, server)
			if err := publisher.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
			ended := tunnelWorker(t, func() { _ = publisher.Close() }, func() error {
				return publisher.(*replyStream).end(t.Context())
			})
			if data, err := io.ReadAll(stream); err != nil || len(data) != 0 {
				t.Fatal("post-TLS deadline prevented clean outer completion", err)
			}
			if err := await(t, ended); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPublicReturnStreamRealResetAndSessionLossJoinCopies(t *testing.T) {
	for _, transport := range []string{"quic", "tls_yamux"} {
		for _, loss := range []bool{false, true} {
			t.Run(transport+map[bool]string{false: "/reset", true: "/session_loss"}[loss], func(t *testing.T) {
				client, server := realTunnelPair(t, transport)
				stream, publisher := realVisitorPair(t, client, server)
				_, front := tunnelTCPPair(t)
				copyDone := tunnelWorker(t, func() { _ = front.Close(); _ = stream.Close() }, func() error { _, err := streamcopy.Copy(front, stream); return err })
				if loss {
					_ = server.Close()
				} else if err := publisher.Reset(17); err != nil {
					t.Fatal(err)
				}
				err := await(t, copyDone)
				if transport == "tls_yamux" {
					if !errors.Is(err, yamux.ErrStreamReset) {
						t.Fatalf("lost reset: %v", err)
					}
					if loss && !errors.Is(err, io.EOF) {
						t.Fatalf("lost joined session EOF: %v", err)
					}
					if !loss {
						var reset *yamux.StreamError
						if !errors.As(err, &reset) || !reset.Remote || reset.ErrorCode != 17 {
							t.Fatalf("lost typed reset: %v", err)
						}
					}
				} else {
					if loss {
						var failure *quic.ApplicationError
						if !errors.As(err, &failure) {
							t.Fatalf("lost session cause: %v", err)
						}
					} else {
						var reset *quic.StreamError
						if !errors.As(err, &reset) || !reset.Remote || reset.ErrorCode != 17 {
							t.Fatalf("lost typed reset: %v", err)
						}
					}
				}
				if loss {
					return
				}
				if client.Err() != nil || server.Err() != nil {
					t.Fatal("stream reset retired session")
				}
				sibling, peer := realVisitorPair(t, client, server)
				if _, err := sibling.Write([]byte("ping")); err != nil {
					t.Fatal(err)
				}
				var ping [4]byte
				if _, err := io.ReadFull(peer, ping[:]); err != nil || string(ping[:]) != "ping" {
					t.Fatal("sibling failed", err)
				}
			})
		}
	}
}
