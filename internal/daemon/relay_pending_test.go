package daemon

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/security/tlspolicy"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

type pendingListener struct {
	connections chan net.Conn
	done        chan struct{}
	once        sync.Once
}

func (l *pendingListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.connections:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *pendingListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *pendingListener) Addr() net.Addr { return &net.TCPAddr{Port: 443} }

type pendingReadConn struct {
	net.Conn
	reading chan struct{}
	once    sync.Once
}

func (c *pendingReadConn) Read(data []byte) (int, error) {
	c.once.Do(func() { close(c.reading) })
	return c.Conn.Read(data)
}

func TestRelayPendingTLSCapacityFailureTimeoutAndCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		listener := &pendingListener{connections: make(chan net.Conn), done: make(chan struct{})}
		done := make(chan error, 1)
		go func() {
			done <- serveWebSocketSessions(ctx, listener, &tls.Config{}, muxsession.WebSocketConfig{}, func(context.Context, context.Context, muxsession.Session, func()) error {
				t.Error("incomplete TLS reached session authentication")
				return nil
			})
		}()
		var peers []net.Conn
		defer func() {
			cancel()
			_ = listener.Close()
			for _, p := range peers {
				_ = p.Close()
			}
			if err := <-done; err != nil {
				t.Error(err)
			}
		}()
		open := func() (net.Conn, <-chan struct{}) {
			peer, server := net.Pipe()
			peers = append(peers, peer)
			started := make(chan struct{})
			listener.connections <- &pendingReadConn{Conn: server, reading: started}
			return peer, started
		}
		for range relayPendingTLSLimit {
			_, reading := open()
			<-reading
		}
		rejected, reading := open()
		if _, err := rejected.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatal("saturated setup was not closed", err)
		}
		select {
		case <-reading:
			t.Fatal("saturated setup started a TLS worker")
		default:
		}
		// failure releases one pending slot without waiting for its deadline.
		_ = peers[0].Close()
		synctest.Wait()
		_, reading = open()
		<-reading
		// the existing absolute setup deadline releases every remaining slot.
		time.Sleep(relaySessionSetupTimeout + time.Second)
		synctest.Wait()
		_, reading = open()
		<-reading
		cancel()
		synctest.Wait()
	})
}

func TestRelaySuccessfulTLSDoesNotRetainPendingSlot(t *testing.T) {
	for _, authenticate := range []bool{false, true} {
		t.Run(map[bool]string{false: "upgrade_still_pending", true: "authenticated"}[authenticate], func(t *testing.T) {
			cert := visitorfixture.Certificate(t, "relay.example.test")
			verifiedAt := time.Now()
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				listener := &pendingListener{connections: make(chan net.Conn), done: make(chan struct{})}
				done, accepted := make(chan error, 1), make(chan struct{})
				go func() {
					done <- serveWebSocketSessions(ctx, listener, &tls.Config{Certificates: []tls.Certificate{cert}}, muxsession.WebSocketConfig{}, func(ctx, setup context.Context, session muxsession.Session, authenticated func()) error {
						if authenticate {
							authenticated()
						}
						close(accepted)
						if !authenticate {
							<-setup.Done()
							return session.Close()
						}
						<-ctx.Done()
						return session.Close()
					})
				}()
				var peers []net.Conn
				defer func() {
					cancel()
					_ = listener.Close()
					for _, peer := range peers {
						_ = peer.Close()
					}
					if err := <-done; err != nil {
						t.Error(err)
					}
				}()
				for range relayPendingTLSLimit - 1 {
					peer, server := net.Pipe()
					peers = append(peers, peer)
					reading := make(chan struct{})
					listener.connections <- &pendingReadConn{Conn: server, reading: reading}
					<-reading
				}
				peer, server := net.Pipe()
				peers = append(peers, peer)
				listener.connections <- server
				config := tlspolicy.RequirePostQuantum(&tls.Config{ServerName: "relay.example.test", RootCAs: visitorfixture.Roots(t, cert), NextProtos: []string{"http/1.1"}})
				config.Time = func() time.Time { return verifiedAt }
				client := tls.Client(peer, config)
				if err := client.HandshakeContext(ctx); err != nil {
					t.Fatal(err)
				}
				if _, err := io.WriteString(client, "GET "+muxsession.WebSocketPath+" HTTP/1.1\r\nHost: relay.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==\r\nSec-WebSocket-Protocol: "+muxsession.WebSocketProtocol+"\r\n\r\n"); err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(bufio.NewReader(client), nil)
				if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
					t.Fatal("websocket upgrade failed", err)
				}
				<-accepted
				// the admitted callback is still running, but its pending slot is free.
				peer, server = net.Pipe()
				peers = append(peers, peer)
				reading := make(chan struct{})
				listener.connections <- &pendingReadConn{Conn: server, reading: reading}
				if !authenticate {
					synctest.Wait()
					select {
					case <-reading:
						t.Fatal("websocket upgrade released unauthenticated capacity")
					default:
					}
					return
				}
				<-reading
			})
		})
	}
}
