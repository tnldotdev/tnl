package peer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
)

// the target protocol has a monotonic exchange counter scoped to one real TCP
// connection. neither replacing the target socket nor replaying a request can
// satisfy the transcript across relay/direct/alternate-relay transitions.
func TestPeerSwitchingPreservesTCPConnection(t *testing.T) {
	for _, tcp := range []bool{false, true} {
		for _, direct := range []bool{false, true} {
			t.Run(fmt.Sprintf("tcp-relay=%t/direct=%t", tcp, direct), func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
				defer cancel()
				serverTLS, clientTLS := peerTLS(t)
				var gate [pathCount]*atomic.Bool
				var clientPaths, serverPaths [pathCount]Carrier
				for index := range pathCount {
					gate[index] = new(atomic.Bool)
					var left, right Carrier
					if index == Direct {
						left, right = directPair(t)
						gate[index].Store(true)
					} else {
						left, right = relayPair(t, ctx, tcp, serverTLS, clientTLS)
					}
					clientPaths[index] = &gatedCarrier{Carrier: left, drop: gate[index]}
					serverPaths[index] = &gatedCarrier{Carrier: right, drop: gate[index]}
				}
				var key [32]byte
				if _, err := rand.Read(key[:]); err != nil {
					t.Fatal(err)
				}
				makeEndpoint := func(role uint8, paths [pathCount]Carrier) *Endpoint {
					e, err := New(ctx, Config{Key: key, Role: role, Paths: paths, ProbeInterval: 25 * time.Millisecond, PathTimeout: 150 * time.Millisecond})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = e.Close() })
					return e
				}
				clientEndpoint := makeEndpoint(0, clientPaths)
				serverEndpoint := makeEndpoint(1, serverPaths)
				clientTransport := &quic.Transport{Conn: clientEndpoint}
				serverTransport := &quic.Transport{Conn: serverEndpoint}
				t.Cleanup(func() { _ = clientTransport.Close(); _ = serverTransport.Close() })
				config := &quic.Config{InitialPacketSize: 1200, DisablePathMTUDiscovery: true, MaxIdleTimeout: 5 * time.Second, KeepAlivePeriod: 100 * time.Millisecond}
				listener, err := serverTransport.Listen(serverTLS, config)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = listener.Close() })
				client, err := clientTransport.Dial(ctx, clientEndpoint.RemoteAddr(), clientTLS, config)
				if err != nil {
					t.Fatal("relay-first end-to-end QUIC", err)
				}
				server, err := listener.Accept(ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = client.CloseWithError(0, ""); _ = server.CloseWithError(0, "") })
				stream, err := client.OpenStreamSync(ctx)
				if err != nil {
					t.Fatal(err)
				}
				// QUIC streams become visible after their first byte.
				if _, err := stream.Write([]byte{1}); err != nil {
					t.Fatal(err)
				}
				incoming, err := server.AcceptStream(ctx)
				if err != nil {
					t.Fatal(err)
				}
				var start [1]byte
				if _, err := io.ReadFull(incoming, start[:]); err != nil {
					t.Fatal(err)
				}
				visitor, visitorSide := tcpPair(t)
				targetSide, target := tcpPair(t)
				var workers sync.WaitGroup
				results := make(chan error, 3)
				workers.Go(func() { _, err := streamcopy.Copy(visitorSide, &streamConn{Stream: stream}); results <- err })
				workers.Go(func() { _, err := streamcopy.Copy(&streamConn{Stream: incoming}, targetSide); results <- err })
				workers.Go(func() {
					defer target.Close()
					var sequence uint32
					for {
						b := make([]byte, 16<<10)
						_, err := io.ReadFull(target, b)
						if errors.Is(err, io.EOF) {
							_, err = target.Write([]byte("finished"))
							if err == nil {
								err = target.CloseWrite()
							}
							results <- err
							return
						}
						if err == nil && binary.BigEndian.Uint32(b[:4]) != sequence {
							err = errors.New("target connection state reset or request replayed")
						}
						if err != nil {
							results <- err
							return
						}
						sequence++
						if _, err := target.Write(b); err != nil {
							results <- err
							return
						}
					}
				})
				t.Cleanup(func() {
					_ = visitor.Close()
					_ = visitorSide.Close()
					_ = target.Close()
					_ = targetSide.Close()
					stream.CancelRead(0)
					stream.CancelWrite(0)
					incoming.CancelRead(0)
					incoming.CancelWrite(0)
					workers.Wait()
				})
				if err := visitor.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
					t.Fatal(err)
				}
				var sequence uint32
				exchange := func() {
					t.Helper()
					for range 4 {
						b := bytes.Repeat([]byte{byte(sequence + 1)}, 16<<10)
						binary.BigEndian.PutUint32(b[:4], sequence)
						sequence++
						if _, err := visitor.Write(b); err != nil {
							t.Fatal(err)
						}
						got := make([]byte, len(b))
						if _, err := io.ReadFull(visitor, got); err != nil || !bytes.Equal(got, b) {
							t.Fatal("application transcript changed", err)
						}
					}
				}
				exchange()
				if clientEndpoint.ActivePath() == Direct {
					t.Fatal("blocked ICE delayed or bypassed relay-first traffic")
				}
				if direct {
					gate[Direct].Store(false)
					awaitPath(t, ctx, clientEndpoint, serverEndpoint, Direct)
					exchange()
				}
				// neither a healthy old relay nor direct UDP can conceal the
				// alternate-service recovery assertion.
				gate[Direct].Store(true)
				gate[RelayA].Store(true)
				startRecovery := time.Now()
				exchange()
				awaitPath(t, ctx, clientEndpoint, serverEndpoint, RelayB)
				exchange()
				t.Logf("alternate-relay application recovery: %s", time.Since(startRecovery))
				if direct {
					// recover direct delivery, then lose the other relay service.
					gate[Direct].Store(false)
					awaitPath(t, ctx, clientEndpoint, serverEndpoint, Direct)
					exchange()
					gate[RelayA].Store(false)
					gate[RelayB].Store(true)
					gate[Direct].Store(true)
					exchange()
					awaitPath(t, ctx, clientEndpoint, serverEndpoint, RelayA)
					exchange()
				}
				if err := visitor.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				trailer, err := io.ReadAll(visitor)
				if err != nil || string(trailer) != "finished" {
					t.Fatal("half-close lost the final target response", string(trailer), err)
				}
				workers.Wait()
				for range 3 {
					if err := <-results; err != nil {
						t.Fatal(err)
					}
				}
				for _, endpoint := range []*Endpoint{clientEndpoint, serverEndpoint} {
					for index := range pathCount {
						stats := endpoint.Stats(index)
						if stats.PeakQueuedFrames > packetQueue {
							t.Fatal("unbounded carrier queue", stats)
						}
						t.Logf("role=%d path=%d frames=%d/%d drops=%d peak-queue=%d rtt=%s", endpoint.config.Role, index, stats.SentFrames, stats.ReceivedFrames, stats.DroppedFrames, stats.PeakQueuedFrames, stats.RTT)
					}
				}
			})
		}
	}
}

func awaitPath(t *testing.T, ctx context.Context, left, right *Endpoint, expected int) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for left.ActivePath() != expected || right.ActivePath() != expected {
		select {
		case <-ctx.Done():
			t.Fatalf("path %d not established: left=%d right=%d", expected, left.ActivePath(), right.ActivePath())
		case <-ticker.C:
		}
	}
}

type gatedCarrier struct {
	Carrier
	drop *atomic.Bool
}

func (c *gatedCarrier) Send(ctx context.Context, b []byte) error {
	if c.drop.Load() {
		return nil
	}
	return c.Carrier.Send(ctx, b)
}

type udpCarrier struct {
	conn net.PacketConn
	peer net.Addr
}

func (c *udpCarrier) Send(_ context.Context, b []byte) error {
	_, err := c.conn.WriteTo(b, c.peer)
	return err
}

func (c *udpCarrier) Receive(_ context.Context) ([]byte, error) {
	var b [2048]byte
	for {
		n, source, err := c.conn.ReadFrom(b[:])
		if err != nil {
			return nil, err
		}
		if source.String() == c.peer.String() {
			return bytes.Clone(b[:n]), nil
		}
	}
}

func (c *udpCarrier) Close() error { return c.conn.Close() }

func directPair(t *testing.T) (Carrier, Carrier) {
	t.Helper()
	left, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	right, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		_ = left.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	return &udpCarrier{left, right.LocalAddr()}, &udpCarrier{right, left.LocalAddr()}
}

func relayPair(t *testing.T, ctx context.Context, tcp bool, serverTLS, clientTLS *tls.Config) (Carrier, Carrier) {
	t.Helper()
	left, relayLeft := carrierPair(t, ctx, tcp, serverTLS, clientTLS)
	right, relayRight := carrierPair(t, ctx, tcp, serverTLS, clientTLS)
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	for _, pair := range [][2]Carrier{{relayLeft, relayRight}, {relayRight, relayLeft}} {
		workers.Go(func() {
			for {
				b, err := pair[0].Receive(ctx)
				if err != nil {
					return
				}
				if err := pair[1].Send(ctx, b); err != nil {
					return
				}
			}
		})
	}
	t.Cleanup(func() { cancel(); _ = relayLeft.Close(); _ = relayRight.Close(); workers.Wait() })
	return left, right
}

func carrierPair(t *testing.T, ctx context.Context, tcp bool, serverTLS, clientTLS *tls.Config) (Carrier, Carrier) {
	t.Helper()
	if !tcp {
		listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{EnableDatagrams: true, InitialPacketSize: 1200, DisablePathMTUDiscovery: true})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		left, err := quic.DialAddr(ctx, listener.Addr().String(), clientTLS, &quic.Config{EnableDatagrams: true, InitialPacketSize: 1200, DisablePathMTUDiscovery: true})
		if err != nil {
			t.Fatal(err)
		}
		right, err := listener.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = left.CloseWithError(0, ""); _ = right.CloseWithError(0, "") })
		return DatagramCarrier{left}, DatagramCarrier{right}
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	type result struct {
		session muxsession.Session
		err     error
	}
	accepted := make(chan result, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			accepted <- result{err: err}
			return
		}
		s, err := muxsession.AcceptConnectorMuxTLS(ctx, raw, serverTLS, muxsession.TLSYamuxConfig{})
		accepted <- result{s, err}
	}()
	left, err := (muxsession.ConnectorMuxTLS{TLSConfig: clientTLS}).Connect(ctx, muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "peer.test"})
	if err != nil {
		t.Fatal(err)
	}
	right := <-accepted
	if right.err != nil {
		t.Fatal(right.err)
	}
	t.Cleanup(func() { _ = left.Close(); _ = right.session.Close() })
	stream, err := left.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	other, err := right.session.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return &StreamCarrier{Conn: stream}, &StreamCarrier{Conn: other}
}

func peerTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"peer.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	server := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{muxsession.ConnectorALPN}}
	client := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "peer.test", NextProtos: []string{muxsession.ConnectorALPN}}
	return server, client
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	left, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	right, err := listener.AcceptTCP()
	if err != nil {
		_ = left.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	return left, right
}

type streamConn struct{ *quic.Stream }

func (s *streamConn) LocalAddr() net.Addr  { return logicalAddr(0) }
func (s *streamConn) RemoteAddr() net.Addr { return logicalAddr(1) }
func (s *streamConn) CloseWrite() error    { return s.Stream.Close() }
func (s *streamConn) Close() error {
	s.CancelRead(0)
	s.CancelWrite(0)
	return nil
}
