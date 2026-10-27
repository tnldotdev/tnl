package service

import (
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/peer"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestPeerPacketsKeepPublisherAdmissionAndOneTargetAcrossCarrierFailure(t *testing.T) {
	target, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	_, bound, _, verification := privateFixture(t, target.Addr().String())
	binding := peerAdmissionFixture(t, bound)
	owner, err := bound.BindPeer(t.Context(), binding)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	var outgoing, incoming [3]peer.Carrier
	for slot := range 2 {
		client, server := net.Pipe()
		outgoing[slot], incoming[slot] = &peer.StreamCarrier{Conn: client}, &peer.StreamCarrier{Conn: server}
	}
	finished := make(chan error, 1)
	go func() { finished <- owner.ServePackets(t.Context(), incoming) }()
	packets, err := peer.New(t.Context(), peer.Config{Kind: peer.NativePeer, Role: 0, Key: binding.key, Paths: outgoing})
	if err != nil {
		t.Fatal(err)
	}
	defer packets.Close()
	transport := &quic.Transport{Conn: packets}
	defer transport.Close()
	trust := verification.Clone()
	trust.MinVersion, trust.NextProtos = tls.VersionTLS13, []string{tunnelv1.ALPN}
	connection, err := transport.Dial(t.Context(), packets.RemoteAddr(), trust,
		&quic.Config{InitialPacketSize: tunnelv1.MaxPeerPacketBytes, DisablePathMTUDiscovery: true, MaxIdleTimeout: 15 * time.Second})
	if err != nil {
		t.Fatal("inner QUIC did not authenticate the prepared service", err)
	}
	session, err := muxsession.AdoptQUIC(connection)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	stream, err := session.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(12 * time.Second))
	entry := peerVisitorOpening(t, bound, binding, "vc_"+strings.Repeat("v", 22), nil)
	if _, err := tunnelv1.WriteNativePeerVisitorOpening(stream, entry, nil); err != nil {
		t.Fatal(err)
	}
	visitor := tls.Client(tunnel.NewNativeRequestWriter(stream), verification)
	if err := visitor.HandshakeContext(t.Context()); err != nil {
		t.Fatal("inner visitor TLS failed", err)
	}
	_ = target.SetDeadline(time.Now().Add(3 * time.Second))
	backend, err := target.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	_ = backend.SetDeadline(time.Now().Add(12 * time.Second))
	echoDone := make(chan error, 1)
	go func() {
		for expected := byte(1); expected <= 2; expected++ {
			var data [1]byte
			if _, err := io.ReadFull(backend, data[:]); err != nil {
				echoDone <- err
				return
			}
			if data[0] != expected {
				echoDone <- io.ErrUnexpectedEOF
				return
			}
			if _, err := backend.Write(data[:]); err != nil {
				echoDone <- err
				return
			}
		}
		echoDone <- nil
	}()
	exchange := func(value byte) {
		t.Helper()
		if _, err := visitor.Write([]byte{value}); err != nil {
			t.Fatal(err)
		}
		var response [1]byte
		if _, err := io.ReadFull(visitor, response[:]); err != nil || response[0] != value {
			t.Fatal("carrier change lost the admitted stream", err)
		}
	}
	exchange(1)
	_ = outgoing[0].Close()
	exchange(2)
	if err := <-echoDone; err != nil {
		t.Fatal(err)
	}
	if connection.Context().Err() != nil || packets.ActivePath() != peer.RelayB {
		t.Fatal("delivery failure replaced the inner session instead of its carrier")
	}
	bound.mu.Lock()
	admissions, visitors := bound.reservedStreams, len(owner.seen)
	bound.mu.Unlock()
	if admissions != 1 || visitors != 1 {
		t.Fatal("carrier change repeated admission", admissions, visitors)
	}
	_ = target.SetDeadline(time.Now().Add(20 * time.Millisecond))
	if extra, err := target.Accept(); err == nil {
		_ = extra.Close()
		t.Fatal("carrier change dialed a second target connection")
	}
	owner.Close()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal("packet owner shutdown", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("packet workers survived peer closure")
	}
}
