package peer

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
)

func TestPublicIngressChangesUDPAndTCPWithoutRelaysOrICE(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	serverTLS, clientTLS := peerTLS(t)
	udpLeft, udpRight := relayPair(t, ctx, false, serverTLS, clientTLS)
	tcpLeft, tcpRight := relayPair(t, ctx, true, serverTLS, clientTLS)
	udpLost, tcpLost := new(atomic.Bool), new(atomic.Bool)
	var publisherPaths, ingressPaths [pathCount]Carrier
	publisherPaths[IngressUDP], ingressPaths[IngressUDP] = &gatedCarrier{Carrier: udpLeft, drop: udpLost}, &gatedCarrier{Carrier: udpRight, drop: udpLost}
	publisherPaths[IngressTCP], ingressPaths[IngressTCP] = &gatedCarrier{Carrier: tcpLeft, drop: tcpLost}, &gatedCarrier{Carrier: tcpRight, drop: tcpLost}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	makeEndpoint := func(role uint8, paths [pathCount]Carrier) *Endpoint {
		e, err := New(ctx, Config{Kind: PublicIngress, Key: key, Role: role, Paths: paths, ProbeInterval: 25 * time.Millisecond, PathTimeout: 150 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = e.Close() })
		return e
	}
	publisher := makeEndpoint(0, publisherPaths)
	ingress := makeEndpoint(1, ingressPaths)
	if publisher.LocalAddr().String() != "publisher" || publisher.RemoteAddr().String() != "ingress" {
		t.Fatal("public peer roles were labeled as native connector/relay roles")
	}
	if _, err := New(ctx, Config{Kind: PublicIngress, Key: key, Role: 0, Paths: [pathCount]Carrier{publisherPaths[0], publisherPaths[1], NewCarrierSlot()}}); !errors.Is(err, ErrConfiguration) {
		t.Fatal("public publication accepted an ICE or relay path", err)
	}
	clientTransport := &quic.Transport{Conn: publisher}
	serverTransport := &quic.Transport{Conn: ingress}
	t.Cleanup(func() { _ = clientTransport.Close(); _ = serverTransport.Close() })
	config := &quic.Config{InitialPacketSize: 1200, DisablePathMTUDiscovery: true, MaxIdleTimeout: 5 * time.Second, KeepAlivePeriod: 100 * time.Millisecond}
	listener, err := serverTransport.Listen(serverTLS, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	client, err := clientTransport.Dial(ctx, publisher.RemoteAddr(), clientTLS, config)
	if err != nil {
		t.Fatal("publisher-initiated public peer session", err)
	}
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseWithError(0, ""); _ = server.CloseWithError(0, "") })
	// ingress opens each visitor stream on the publisher-initiated session.
	stream, err := server.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	incoming, err := client.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var initial [1]byte
	if _, err := io.ReadFull(incoming, initial[:]); err != nil || initial[0] != 1 {
		t.Fatal("public ingress could not accept one visitor stream", err)
	}
	exchange := func(letter byte) {
		t.Helper()
		if _, err := stream.Write([]byte{letter}); err != nil {
			t.Fatal(err)
		}
		var data [1]byte
		if _, err := io.ReadFull(incoming, data[:]); err != nil || data[0] != letter {
			t.Fatalf("ingress stream changed after carrier switch: %q %v", data, err)
		}
		if _, err := incoming.Write(data[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(stream, data[:]); err != nil || data[0] != letter {
			t.Fatalf("publisher stream changed after carrier switch: %q %v", data, err)
		}
	}
	awaitPath(t, ctx, publisher, ingress, IngressUDP)
	exchange('a')
	udpLost.Store(true)
	awaitPath(t, ctx, publisher, ingress, IngressTCP)
	exchange('b')
	udpLost.Store(false)
	tcpLost.Store(true)
	awaitPath(t, ctx, publisher, ingress, IngressUDP)
	exchange('c')
}
