package publisher

import (
	"errors"
	"net/http"
	"testing"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestPublicURLStreamCapacityIsSharedAcrossRelaySlots(t *testing.T) {
	first := tunnelv1.PublisherConnectionRef{PublicURLID: "url-1", PublishRunID: "run-1", PublishRunNumber: 1, PublisherConnectionID: "connection-1", ConnectionAssignmentRevision: 1, RelayServiceID: "relay-1"}
	second := first
	second.ConnectionSlot, second.PublisherConnectionID, second.RelayServiceID = 1, "connection-2", "relay-2"
	r, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", PublicURLID: first.PublicURLID, PublishRunID: first.PublishRunID, PublishRunNumber: 1,
		Handler: http.NotFoundHandler(), StreamCapacity: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
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
		return relays[index].OpenVisitorStream(t.Context(), tunnelv1.VisitorStreamHeader{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.VisitorStream,
			VisitorConnectionID: visitor, PublicURLID: ref.PublicURLID, PublishRunID: ref.PublishRunID, PublishRunNumber: ref.PublishRunNumber,
			PublisherConnectionID: ref.PublisherConnectionID, ConnectionAssignmentRevision: ref.ConnectionAssignmentRevision})
	}
	stream, err := open(0, "visitor-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	if extra, err := open(1, "visitor-2"); err == nil {
		_ = extra.Close()
		t.Fatal("second relay connection exceeded the shared public run capacity")
	} else {
		var rejected *tunnel.ProtocolError
		if !errors.As(err, &rejected) || rejected.Code != tunnelv1.CapacityExceeded {
			t.Fatal("unexpected overload rejection", err)
		}
	}
	// a partial setup owns its slot until it closes, without reaching a target.
	_ = stream.Close()
	r.handlers.Wait()
	replacement, err := open(1, "visitor-3")
	if err != nil {
		t.Fatal("partial setup leaked its run slot", err)
	}
	_ = replacement.Close()
}
