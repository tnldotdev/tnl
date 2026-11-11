package muxsession

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

type inspectingQUICDialer struct {
	t      *testing.T
	roots  *tls.Config
	config *quic.Config
	err    error
}

func (d inspectingQUICDialer) DialQUIC(_ context.Context, addr net.Addr, trust *tls.Config, config *quic.Config) (*quic.Conn, error) {
	d.t.Helper()
	udp, ok := addr.(*net.UDPAddr)
	if !ok || udp.IP == nil || udp.Port != 443 {
		d.t.Fatal("borrowed dialer did not receive a resolved UDP address", addr)
	}
	if trust == d.roots || trust.ServerName != "relay.test" || trust.MinVersion != tls.VersionTLS13 || !reflect.DeepEqual(trust.NextProtos, []string{ALPN}) {
		d.t.Fatal("borrowed dialer lost cloned TLS/ALPN configuration")
	}
	if !reflect.DeepEqual(trust.CurvePreferences, []tls.CurveID{tls.X25519MLKEM768}) {
		d.t.Fatal("borrowed dialer lost required hybrid post-quantum key agreement")
	}
	if config == d.config || config.Allow0RTT || config.InitialPacketSize != 1200 || config.KeepAlivePeriod != defaultQUICKeepAlivePeriod || !config.EnableDatagrams {
		d.t.Fatal("borrowed dialer lost cloned QUIC configuration")
	}
	return nil, d.err
}

func TestQUICBorrowedDialerResolvesAndPreservesTransportConfiguration(t *testing.T) {
	_, roots := testTLSConfigs(t)
	config := &quic.Config{Allow0RTT: true, EnableDatagrams: true}
	sentinel := errors.New("borrowed dial failure")
	_, err := (QUICConnector{TLSConfig: roots, Config: QUICConfig{Config: config}, Dialer: inspectingQUICDialer{t, roots, config, sentinel}}).Connect(t.Context(), Endpoint{Address: "localhost:443", ServerName: "relay.test"})
	if !errors.Is(err, sentinel) {
		t.Fatal("borrowed dial failure was not preserved", err)
	}
	if roots.ServerName != "" || len(roots.NextProtos) != 0 || !config.Allow0RTT || config.InitialPacketSize != 0 || config.KeepAlivePeriod != 0 {
		t.Fatal("connector modified caller-owned configuration")
	}
}

func TestNonQUICChildCloseAndDeadlinesLeaveSharedQUICAlive(t *testing.T) {
	for _, pinned := range []bool{false, true} {
		t.Run(map[bool]string{false: "transport", true: "source-pinned"}[pinned], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			serverTLS, clientTLS := testTLSConfigs(t)
			config := QUICConfig{}
			if pinned {
				config.PinnedRemoteIPLimit = 4
			}
			listener, err := ListenQUIC("127.0.0.1:0", serverTLS, config)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			serverPackets := listener.NonQUICPackets(ctx)
			defer serverPackets.Close()
			duplicate := listener.NonQUICPackets(ctx)
			if _, _, err := duplicate.ReadFrom(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
				t.Fatal("listener allowed a competing non-QUIC reader", err)
			}
			transport := testQUICTransport(t)
			clientPackets := transport.NonQUICPackets(ctx)
			defer clientPackets.Close()
			client, err := (QUICConnector{TLSConfig: clientTLS, Dialer: transport}).Connect(ctx, Endpoint{Address: listener.Addr().String(), ServerName: "relay.test"})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			server, err := listener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			for _, child := range []net.PacketConn{serverPackets, clientPackets} {
				// an expired read also initializes quic-go's lazy non-QUIC queue.
				_ = child.SetReadDeadline(time.Now().Add(-time.Second))
				if _, _, err := child.ReadFrom(make([]byte, 64)); !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatal("child did not enforce its read deadline", err)
				}
				_ = child.SetReadDeadline(time.Now().Add(time.Second))
				if err := child.SetWriteDeadline(time.Now().Add(time.Second)); !errors.Is(err, errors.ErrUnsupported) {
					t.Fatal("child tried to change the shared write deadline", err)
				}
			}
			if _, err := clientPackets.WriteTo([]byte("\x00binding request"), listener.Addr()); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 64)
			n, reply, err := serverPackets.ReadFrom(buffer)
			if err != nil || string(buffer[:n]) != "\x00binding request" {
				t.Fatal("shared socket did not deliver a non-QUIC packet", err)
			}
			if _, err := serverPackets.WriteTo([]byte("\x00binding response"), reply); err != nil {
				t.Fatal(err)
			}
			n, _, err = clientPackets.ReadFrom(buffer)
			if err != nil || string(buffer[:n]) != "\x00binding response" {
				t.Fatal("shared socket lost the non-QUIC reply", err)
			}
			assertRoundTrip(t, client, server, "after child deadlines")
			for _, child := range []net.PacketConn{serverPackets, clientPackets} {
				_ = child.SetReadDeadline(time.Time{})
				done := make(chan error, 1)
				go func() { _, _, err := child.ReadFrom(buffer); done <- err }()
				_ = child.Close()
				select {
				case err := <-done:
					if !errors.Is(err, net.ErrClosed) {
						t.Fatal("closing child did not interrupt its reader", err)
					}
				case <-ctx.Done():
					t.Fatal("child reader was not joined")
				}
				if _, err := child.WriteTo([]byte("closed"), listener.Addr()); !errors.Is(err, net.ErrClosed) {
					t.Fatal("closed child could still write", err)
				}
			}
			assertRoundTrip(t, client, server, "after both packet children close")
			if got := client.(AcceptedPeer).LocalAddr().String(); got != transport.LocalAddr().String() {
				t.Fatal("borrowed dialer did not use the existing physical socket", got)
			}
		})
	}
}

func TestNonQUICDeadlineChangesInterruptOnlyChildRead(t *testing.T) {
	entered := make(chan struct{}, 4)
	child := newNonQUICPacketConn(t.Context(), &net.UDPAddr{}, func(ctx context.Context, _ []byte) (int, net.Addr, error) {
		entered <- struct{}{}
		<-ctx.Done()
		return 0, nil, context.Cause(ctx)
	}, func(b []byte, _ net.Addr) (int, error) { return len(b), nil })
	defer child.Close()
	done := make(chan error, 1)
	go func() { _, _, err := child.ReadFrom(make([]byte, 64)); done <- err }()
	<-entered
	_ = child.SetReadDeadline(time.Now().Add(time.Hour))
	<-entered
	_ = child.SetReadDeadline(time.Time{})
	<-entered
	_ = child.SetReadDeadline(time.Now().Add(-time.Second))
	if err := <-done; !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("deadline change did not interrupt the active child read", err)
	}
	if _, err := child.WriteTo([]byte("alive"), &net.UDPAddr{}); err != nil {
		t.Fatal("read deadline affected writes", err)
	}
}

func TestNonQUICParentCancellationJoinsChildReader(t *testing.T) {
	parent, cancel := context.WithCancel(t.Context())
	defer cancel()
	entered := make(chan struct{})
	child := newNonQUICPacketConn(parent, &net.UDPAddr{}, func(ctx context.Context, _ []byte) (int, net.Addr, error) {
		close(entered)
		<-ctx.Done()
		return 0, nil, context.Cause(ctx)
	}, func(b []byte, _ net.Addr) (int, error) { return len(b), nil })
	defer child.Close()
	done := make(chan error, 1)
	go func() { _, _, err := child.ReadFrom(make([]byte, 64)); done <- err }()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, net.ErrClosed) {
		t.Fatal("parent cancellation did not interrupt its child read", err)
	}
	if _, err := child.WriteTo([]byte("closed"), &net.UDPAddr{}); !errors.Is(err, net.ErrClosed) {
		t.Fatal("parent cancellation left its child writable", err)
	}
}
