package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

func stunTestRequest() []byte {
	request := make([]byte, 64)
	binary.BigEndian.PutUint16(request, 1)
	binary.BigEndian.PutUint16(request[2:], uint16(len(request)-20))
	binary.BigEndian.PutUint32(request[4:], stunCookie)
	copy(request[8:20], "transaction1")
	binary.BigEndian.PutUint16(request[20:], 0x0026)
	binary.BigEndian.PutUint16(request[22:], 40)
	return request
}

func TestSTUNBindingResponseIsBoundedDiscoveryOnly(t *testing.T) {
	for _, ip := range []string{"192.0.2.1", "2001:db8::1"} {
		t.Run(ip, func(t *testing.T) {
			request := stunTestRequest()
			source := &net.UDPAddr{IP: net.ParseIP(ip), Port: 54321}
			response := stunBindingResponse(request, source)
			assertSTUNTestResponse(t, request, response, source)
		})
	}
	source := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 54321}
	for name, mutate := range map[string]func([]byte) []byte{
		"empty":              func([]byte) []byte { return nil },
		"truncated":          func(b []byte) []byte { return b[:19] },
		"amplification":      func(b []byte) []byte { b = b[:20]; binary.BigEndian.PutUint16(b[2:], 0); return b },
		"oversized":          func(b []byte) []byte { return append(b, make([]byte, 512)...) },
		"wrong cookie":       func(b []byte) []byte { b[4] = 0; return b },
		"wrong method":       func(b []byte) []byte { b[1] = 3; return b },
		"response":           func(b []byte) []byte { b[0] = 1; return b },
		"username":           func(b []byte) []byte { binary.BigEndian.PutUint16(b[20:], 6); return b },
		"integrity":          func(b []byte) []byte { binary.BigEndian.PutUint16(b[20:], 8); return b },
		"ICE check":          func(b []byte) []byte { binary.BigEndian.PutUint16(b[20:], 0x802a); return b },
		"length mismatch":    func(b []byte) []byte { b[3]--; return b },
		"attribute overflow": func(b []byte) []byte { binary.BigEndian.PutUint16(b[22:], 65535); return b },
		"bad fingerprint":    func(b []byte) []byte { binary.BigEndian.PutUint16(b[20:], 0x8028); return b },
	} {
		t.Run(name, func(t *testing.T) {
			if got := stunBindingResponse(mutate(stunTestRequest()), source); got != nil {
				t.Fatal("invalid or non-discovery request received a response")
			}
		})
	}
	request := append(stunTestRequest(), make([]byte, 8)...)
	binary.BigEndian.PutUint16(request[2:], uint16(len(request)-20))
	binary.BigEndian.PutUint16(request[64:], 0x8028)
	binary.BigEndian.PutUint16(request[66:], 4)
	binary.BigEndian.PutUint32(request[68:], crc32.ChecksumIEEE(request[:64])^stunFingerprint)
	if stunBindingResponse(request, source) == nil {
		t.Fatal("valid fingerprint was rejected")
	}
	request[68] ^= 1
	if stunBindingResponse(request, source) != nil {
		t.Fatal("invalid fingerprint was accepted")
	}
	for _, address := range []*net.UDPAddr{nil, {IP: nil, Port: 1}, {IP: net.IPv4zero, Port: 1}, {IP: net.IPv4(224, 0, 0, 1), Port: 1}, {IP: source.IP, Port: 0}, {IP: source.IP, Port: 65536}, {IP: source.IP, Port: 1, Zone: "en0"}} {
		if stunBindingResponse(stunTestRequest(), address) != nil {
			t.Fatal("invalid source received a discovery response")
		}
	}
}

func assertSTUNTestResponse(t *testing.T, request, response []byte, source *net.UDPAddr) {
	t.Helper()
	ip := source.IP.To4()
	family := byte(1)
	if ip == nil {
		ip, family = source.IP.To16(), 2
	}
	if len(response) != 36+len(ip) || len(response) > len(request) || binary.BigEndian.Uint16(response) != 0x0101 || !bytes.Equal(response[4:20], request[4:20]) {
		t.Fatal("response lost transaction identity, wire shape, or no-amplification bound")
	}
	if response[25] != family || binary.BigEndian.Uint16(response[26:])^uint16(stunCookie>>16) != uint16(source.Port) {
		t.Fatal("incorrect mapped address family or port")
	}
	for i := range ip {
		if response[28+i]^request[4+i] != ip[i] {
			t.Fatal("incorrect mapped source IP")
		}
	}
	at := len(response) - 8
	if binary.BigEndian.Uint32(response[at+4:]) != crc32.ChecksumIEEE(response[:at])^stunFingerprint {
		t.Fatal("response fingerprint is invalid")
	}
}

type stunFloodPackets struct {
	input  chan []byte
	done   chan struct{}
	once   sync.Once
	writes int
}

func (p *stunFloodPackets) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case raw := <-p.input:
		return copy(b, raw), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1234}, nil
	case <-p.done:
		return 0, nil, net.ErrClosed
	}
}
func (p *stunFloodPackets) WriteTo(b []byte, _ net.Addr) (int, error) { p.writes++; return len(b), nil }
func (p *stunFloodPackets) Close() error                              { p.once.Do(func() { close(p.done) }); return nil }
func (*stunFloodPackets) LocalAddr() net.Addr                         { return &net.UDPAddr{} }
func (*stunFloodPackets) SetDeadline(time.Time) error                 { return errors.ErrUnsupported }
func (*stunFloodPackets) SetReadDeadline(time.Time) error             { return errors.ErrUnsupported }
func (*stunFloodPackets) SetWriteDeadline(time.Time) error            { return errors.ErrUnsupported }

type stunCountObserver map[string]int

func (o stunCountObserver) ObserveSTUNBinding(result string) { o[result]++ }

func TestSTUNFloodHasFixedReplyBudgetAndJoinedShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		packets := &stunFloodPackets{input: make(chan []byte, 1000), done: make(chan struct{})}
		for range 1000 {
			packets.input <- stunTestRequest()
		}
		observer := stunCountObserver{}
		done := make(chan error, 1)
		go func() { done <- ServeSTUN(ctx, packets, observer) }()
		synctest.Wait()
		if packets.writes != 100 || observer["accepted"] != 100 || observer["capacity"] != 900 {
			t.Fatal("discovery flood exceeded its fixed burst budget", packets.writes, observer)
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatal("cancelled discovery did not join cleanly", err)
		}
	})
}

func stunTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	server := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return &tls.Config{Certificates: server.TLS.Certificates}, &tls.Config{RootCAs: roots}
}

type stunBorrowedQUICDialer struct{ transport *quic.Transport }

func (d stunBorrowedQUICDialer) DialQUIC(ctx context.Context, addr net.Addr, trust *tls.Config, config *quic.Config) (*quic.Conn, error) {
	return d.transport.Dial(ctx, addr, trust, config)
}

func TestSTUNSharesSourcePinnedQUICSocket(t *testing.T) {
	for _, basic := range []bool{false, true} {
		t.Run(map[bool]string{false: "metadata", true: "basic"}[basic], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			serverTLS, clientTLS := stunTLSConfigs(t)
			listener, err := muxsession.ListenQUIC("127.0.0.1:0", serverTLS, muxsession.QUICConfig{PinnedRemoteIPLimit: 4, BasicPacketConn: basic})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			stunCtx, stopSTUN := context.WithCancel(ctx)
			serverPackets := listener.NonQUICPackets(stunCtx)
			done := make(chan error, 1)
			go func() { done <- ServeSTUN(stunCtx, serverPackets, nil) }()
			defer func() {
				stopSTUN()
				if err := <-done; err != nil {
					t.Error(err)
				}
			}()
			packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer packet.Close()
			transport := &quic.Transport{Conn: packet}
			defer transport.Close()
			client, err := (muxsession.QUICConnector{TLSConfig: clientTLS, Dialer: stunBorrowedQUICDialer{transport}}).Connect(ctx, muxsession.Endpoint{Address: listener.Addr().String(), ServerName: "example.com"})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			server, err := listener.Accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			child := muxsession.NonQUICPacketConn(ctx, transport, packet.LocalAddr())
			defer child.Close()
			_ = child.SetReadDeadline(time.Now().Add(-time.Second))
			if _, _, err := child.ReadFrom(make([]byte, 64)); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal(err)
			}
			_ = child.SetReadDeadline(time.Now().Add(time.Second))
			for range 5 {
				request := stunTestRequest()
				if _, err := child.WriteTo(request, listener.Addr()); err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 512)
				n, _, err := child.ReadFrom(buffer)
				if err != nil {
					t.Fatal(err)
				}
				assertSTUNTestResponse(t, request, buffer[:n], packet.LocalAddr().(*net.UDPAddr))
				assertSTUNSharedStream(t, ctx, client, server)
			}
			stopSTUN()
			// stopping discovery closes only its view, not the live QUIC session.
			assertSTUNSharedStream(t, ctx, client, server)
		})
	}
}

func assertSTUNSharedStream(t *testing.T, ctx context.Context, client, server muxsession.Session) {
	t.Helper()
	stream, err := client.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte("still connected")); err != nil {
		t.Fatal(err)
	}
	accepted, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	buffer := make([]byte, len("still connected"))
	if _, err := io.ReadFull(accepted, buffer); err != nil || string(buffer) != "still connected" {
		t.Fatal("shared QUIC stream failed", err)
	}
}
