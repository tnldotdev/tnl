package publisher

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"testing"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestPublicURLStreamCapacityIsSharedAcrossRelaySlots(t *testing.T) {
	first := tunnelv1.PublisherConnectionRef{PublicURLID: certificateTestPublicURLID, PublishRunID: "pr_0123456789abcdefghijkl", PublishRunNumber: 1, PublisherConnectionID: "connection-1", ConnectionAssignmentRevision: 1, RelayServiceID: "relay-1"}
	second := first
	second.ConnectionSlot, second.PublisherConnectionID, second.RelayServiceID = 1, "connection-2", "relay-2"
	certificate := publicURLTestCertificate(t, "route.example")
	r, err := newTestPublicURLServer(t, PublicURLServerConfig{Hostname: "route.example", PublicURLID: first.PublicURLID, PublishRunID: first.PublishRunID, PublishRunNumber: 1,
		Handler: http.NotFoundHandler(), StreamCapacity: 1, Certificate: certificate})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	var relays [2]*tunnel.Session
	for index, ref := range []tunnelv1.PublisherConnectionRef{first, second} {
		publisher, relay := promotionSessionPair(t, ref)
		relays[index] = relay
		finished := make(chan error, 1)
		go func() { finished <- r.ServePublisherConnection(t.Context(), publisher, ref) }()
		t.Cleanup(func() {
			_ = publisher.Close()
			awaitPublisherTest(t, finished)
		})
	}
	open := func(index int, slot uint32) (muxsession.Stream, error) {
		ref := []tunnelv1.PublisherConnectionRef{first, second}[index]
		return relays[index].StartVisitorStream(t.Context(), tunnelv1.VisitorStreamHeader{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.VisitorStream,
			VisitorConnectionID: testPublicStreamReservation(ref, slot).VisitorConnectionID, Reservation: testPublicStreamReservation(ref, slot), PublicURLID: ref.PublicURLID, PublishRunID: ref.PublishRunID, PublishRunNumber: ref.PublishRunNumber,
			PublisherConnectionID: ref.PublisherConnectionID, ConnectionAssignmentRevision: ref.ConnectionAssignmentRevision}, nil, nil)
	}
	stream, err := open(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	proxy, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.1:1234"), Destination: netip.MustParseAddrPort("127.0.0.1:443")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write(proxy); err != nil {
		t.Fatal(err)
	}
	visitor := tls.Client(stream, &tls.Config{ServerName: "route.example", RootCAs: rootsForCertificate(t, certificate)})
	if err := visitor.HandshakeContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	request := func(client *tls.Conn) int {
		t.Helper()
		if _, err := fmt.Fprint(client, "GET / HTTP/1.1\r\nHost: route.example\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		response, err := http.ReadResponse(bufio.NewReader(client), nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		return response.StatusCode
	}
	if status := request(visitor); status != http.StatusNotFound {
		t.Fatal("first authorized visitor was not served", status)
	}
	extra, err := open(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := extra.Write(proxy); err != nil {
		t.Fatal(err)
	}
	extraTLS := tls.Client(extra, &tls.Config{ServerName: "route.example", RootCAs: rootsForCertificate(t, certificate)})
	if err := extraTLS.HandshakeContext(t.Context()); err != nil {
		t.Fatal("independent relay could not finish bounded setup", err)
	}
	if status := request(extraTLS); status != http.StatusServiceUnavailable {
		t.Fatal("second relay exceeded the shared authorized run capacity", status)
	}
	_ = extraTLS.Close()
	var rejected *tunnel.ProtocolError
	// connection capacity is spent only after current visitor permission. setup
	// on the other relay is independent; admitted overflow still fails globally.
	_ = visitor.Close()
	r.handlers.Wait()
	replayed, err := open(1, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = replayed.Read(make([]byte, 1))
	_ = replayed.Close()
	if !errors.As(err, &rejected) || rejected.Code != tunnelv1.Unauthenticated {
		t.Fatal("other relay replayed a released reservation", err)
	}
	replacement, err := open(1, 2)
	if err != nil {
		t.Fatal("partial setup leaked its run slot", err)
	}
	if _, err := replacement.Write(proxy); err != nil {
		t.Fatal(err)
	}
	replacementTLS := tls.Client(replacement, &tls.Config{ServerName: "route.example", RootCAs: rootsForCertificate(t, certificate)})
	if err := replacementTLS.HandshakeContext(t.Context()); err != nil {
		t.Fatal("fresh reservation did not recover the released run slot", err)
	}
	if status := request(replacementTLS); status != http.StatusNotFound {
		t.Fatal("fresh authorized visitor did not recover shared capacity", status)
	}
	_ = replacementTLS.Close()
}
