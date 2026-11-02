package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func privateTransportTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"relay.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, leaf, public, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, &tls.Config{RootCAs: roots}
}

func TestPrivatePublisherProductionSlotQUICAndTLSNoReplayAfterPathLoss(t *testing.T) {
	for _, transport := range []tunnel.Transport{tunnel.TransportQUIC, tunnel.TransportTLSTCP} {
		t.Run(string(transport), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			target, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			var dials atomic.Int64
			targetClosed := make(chan struct{}, 2)
			go func() {
				for {
					conn, err := target.Accept()
					if err != nil {
						return
					}
					dials.Add(1)
					go func() { defer conn.Close(); defer func() { targetClosed <- struct{}{} }(); _, _ = io.Copy(conn, conn) }()
				}
			}()
			_, bound, ref, verification := privateFixture(t, target.Addr().String())
			serverTLS, roots := privateTransportTLS(t)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			bound.connections[0].RelayAddress, bound.connections[0].TlsServerName = listener.Addr().String(), "relay.test"
			accepted := make(chan *tunnel.Session, 2)
			accept := func(session muxsession.Session) {
				peer, _, err := tunnel.Accept(ctx, session, func(_ context.Context, hello tunnelv1.Message) error {
					if hello.ServiceConnection == nil || *hello.ServiceConnection != ref || hello.Credential != bound.connections[0].PublisherConnectionCredential {
						return errors.New("wrong private assignment")
					}
					return nil
				})
				if err == nil {
					accepted <- peer
				}
			}
			if transport == tunnel.TransportQUIC {
				udp, err := muxsession.ListenQUIC(listener.Addr().String(), serverTLS, muxsession.QUICConfig{Config: &quic.Config{EnableDatagrams: true}})
				if err != nil {
					t.Fatal(err)
				}
				defer udp.Close()
				go func() {
					session, err := udp.Accept(ctx)
					if err == nil {
						accept(session)
					}
				}()
			} else {
				go func() {
					network, err := listener.Accept()
					if err != nil {
						return
					}
					session, err := muxsession.AcceptTLSYamux(ctx, network, serverTLS, muxsession.TLSYamuxConfig{})
					if err == nil {
						accept(session)
					}
				}()
			}
			claimed, err := bound.ConnectSlotWithPreference(ctx, 0, false, roots)
			if err != nil {
				t.Fatal(err)
			}
			defer claimed.Close()
			if claimed.Transport() != transport {
				t.Fatalf("transport = %s", claimed.Transport())
			}
			var relay *tunnel.Session
			select {
			case relay = <-accepted:
			case <-time.After(time.Second):
				t.Fatal("relay never authenticated slot")
			}
			defer relay.Close()
			done := make(chan error, 1)
			go func() { done <- claimed.Serve(ctx) }()
			header := privateHeader(t, ref)
			stream, err := relay.OpenServiceForwardingStream(ctx, header)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			proxy, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.10:40000"), Destination: netip.MustParseAddrPort("203.0.113.1:25443")})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := stream.Write(proxy); err != nil {
				t.Fatal(err)
			}
			secure := tls.Client(stream, verification.Clone())
			if err := secure.HandshakeContext(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := secure.Write([]byte("one opaque command")); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, len("one opaque command"))
			if _, err := io.ReadFull(secure, response); err != nil || string(response) != "one opaque command" {
				t.Fatalf("opaque response: %q %v", response, err)
			}
			_ = relay.Close()
			select {
			case <-targetClosed:
			case <-time.After(3 * time.Second):
				t.Fatal("path loss did not close target")
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("lost slot did not join")
			}
			if dials.Load() != 1 {
				t.Fatalf("live target connection replayed: %d", dials.Load())
			}
		})
	}
}
