package daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
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
			done <- serveTLSYamuxSessions(ctx, listener, &tls.Config{}, muxsession.TLSYamuxConfig{}, func(context.Context, muxsession.Session) error {
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
	cert := visitorfixture.Certificate(t, "relay.example.test")
	verifiedAt := time.Now()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		listener := &pendingListener{connections: make(chan net.Conn), done: make(chan struct{})}
		done, accepted := make(chan error, 1), make(chan struct{})
		go func() {
			done <- serveTLSYamuxSessions(ctx, listener, &tls.Config{Certificates: []tls.Certificate{cert}}, muxsession.TLSYamuxConfig{}, func(ctx context.Context, session muxsession.Session) error {
				close(accepted)
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
		config := tlspolicy.RequirePostQuantum(&tls.Config{ServerName: "relay.example.test", RootCAs: visitorfixture.Roots(t, cert), NextProtos: []string{muxsession.ALPN}})
		config.Time = func() time.Time { return verifiedAt }
		client := tls.Client(peer, config)
		if err := client.HandshakeContext(ctx); err != nil {
			t.Fatal(err)
		}
		<-accepted
		// the admitted callback is still running, but its pending slot is free.
		peer, server = net.Pipe()
		peers = append(peers, peer)
		reading := make(chan struct{})
		listener.connections <- &pendingReadConn{Conn: server, reading: reading}
		<-reading
	})
}
