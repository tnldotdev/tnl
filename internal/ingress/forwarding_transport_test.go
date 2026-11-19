package ingress

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil/transporttest"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestForwarderQUICAndWebSocketAuthenticateBeforePooling(t *testing.T) {
	for _, variant := range []string{"quic", "blocked_udp", "denied"} {
		t.Run(variant, func(t *testing.T) {
			material := newForwardingTestMaterial(t)
			tcp, packet, err := transporttest.ListenTCPUDP()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			var workers sync.WaitGroup
			accepted := make(chan string, 2)
			serverTLS := &tls.Config{Certificates: []tls.Certificate{material.relay}}
			handle := func(transport muxsession.Session, name string) {
				defer transport.Close()
				session, _, err := tunnel.Accept(ctx, transport, func(_ context.Context, hello tunnelv1.Message) error {
					if hello.Role != tunnelv1.Ingress || hello.Credential != forwardingClusterSecret {
						return &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}
					}
					return nil
				})
				if err != nil {
					return
				}
				defer session.Close()
				accepted <- name
				select {
				case <-session.Done():
				case <-ctx.Done():
				}
			}
			var udp *muxsession.QUICListener
			if variant != "blocked_udp" {
				udp, err = muxsession.ListenQUICPacket(packet, serverTLS, muxsession.QUICConfig{})
				if err != nil {
					t.Fatal(err)
				}
				workers.Go(func() {
					for {
						session, err := udp.Accept(ctx)
						if err != nil {
							return
						}
						workers.Go(func() { handle(session, "quic") })
					}
				})
			}
			workers.Go(func() {
				for {
					connection, err := tcp.Accept()
					if err != nil {
						return
					}
					workers.Go(func() {
						stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
						defer stop()
						session, err := muxsession.AcceptWebSocket(ctx, connection, serverTLS, muxsession.WebSocketConfig{})
						if err == nil {
							handle(session, "wss")
						}
					})
				}
			})
			secret := forwardingClusterSecret
			if variant == "denied" {
				secret = "wrong-secret"
			}
			forwarder, err := NewForwarder(ForwarderConfig{Context: ctx, TLSConfig: &tls.Config{RootCAs: material.roots}, ClusterSecret: secret})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				_ = forwarder.Close()
				cancel()
				_ = tcp.Close()
				if udp != nil {
					_ = udp.Close()
				} else {
					_ = packet.Close()
				}
				workers.Wait()
			}()
			target := relayTarget{address: tcp.Addr().String(), serverName: material.serverName, relayServiceID: "relay", relayID: "process", relayRunID: "run", relayLeaseRevision: 1}
			session, reused, err := forwarder.session(ctx, target)
			if variant == "denied" {
				var rejection *tunnel.ProtocolError
				if session != nil || !errors.As(err, &rejection) || rejection.Code != tunnelv1.Unauthenticated {
					t.Fatal("unauthenticated transport entered the pool", err)
				}
				return
			}
			if err != nil || reused {
				t.Fatal("initial pooled session", err, reused)
			}
			want := "quic"
			if variant == "blocked_udp" {
				want = "wss"
			}
			select {
			case got := <-accepted:
				if got != want {
					t.Fatalf("transport=%s; want %s", got, want)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			same, reused, err := forwarder.session(ctx, target)
			if err != nil || !reused || same != session {
				t.Fatal("visitor did not reuse selected session", err)
			}
		})
	}
}
