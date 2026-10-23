package publisher

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/netip"
	"testing"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/proxyproto"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestPublicURLStreamCapacityIsSharedAcrossRelaySlots(t *testing.T) {
	first := tunnelv1.PublisherConnectionRef{PublicURLID: "url-1", PublishRunID: "run-1", PublishRunNumber: 1, PublisherConnectionID: "connection-1", ConnectionAssignmentRevision: 1, RelayServiceID: "relay-1"}
	second := first
	second.ConnectionSlot, second.PublisherConnectionID, second.RelayServiceID = 1, "connection-2", "relay-2"
	certificate := publicURLTestCertificate(t, "route.example")
	r, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", PublicURLID: first.PublicURLID, PublishRunID: first.PublishRunID, PublishRunNumber: 1,
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
	open := func(index int, visitor string) (muxsession.Stream, error) {
		ref := []tunnelv1.PublisherConnectionRef{first, second}[index]
		return relays[index].StartVisitorStream(t.Context(), tunnelv1.VisitorStreamHeader{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.VisitorStream,
			VisitorConnectionID: visitor, PublicURLID: ref.PublicURLID, PublishRunID: ref.PublishRunID, PublishRunNumber: ref.PublishRunNumber,
			PublisherConnectionID: ref.PublisherConnectionID, ConnectionAssignmentRevision: ref.ConnectionAssignmentRevision}, nil, nil)
	}
	stream, err := open(0, "visitor-1")
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
	extra, err := open(1, "visitor-2")
	if err != nil {
		t.Fatal(err)
	}
	_, err = extra.Read(make([]byte, 1))
	_ = extra.Close()
	var rejected *tunnel.ProtocolError
	if !errors.As(err, &rejected) || rejected.Code != tunnelv1.CapacityExceeded {
		t.Fatal("second relay exceeded the shared run capacity or changed its rejection", err)
	}
	// a partial setup owns its slot until it closes, without reaching a target.
	_ = visitor.Close()
	r.handlers.Wait()
	replacement, err := open(1, "visitor-3")
	if err != nil {
		t.Fatal("partial setup leaked its run slot", err)
	}
	_ = replacement.Close()
}
