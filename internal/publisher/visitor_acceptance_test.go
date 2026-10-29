package publisher

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestVisitorAcceptanceFailureStaysStreamLocal(t *testing.T) {
	ref := tunnelv1.PublisherConnectionRef{PublicURLID: "url-1", PublishRunID: "run-1", PublishRunNumber: 1, PublisherConnectionID: "connection-1", ConnectionAssignmentRevision: 1, RelayServiceID: "relay-1"}
	publisher, relay := promotionSessionPair(t, ref)
	route, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "route.example", PublicURLID: ref.PublicURLID, PublishRunID: ref.PublishRunID, PublishRunNumber: ref.PublishRunNumber, Handler: http.NotFoundHandler()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = route.Close() })
	live, err := route.registerPublisherSession(t.Context(), publisher, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer route.unregisterPublisherSession(live)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	h := tunnelv1.VisitorStreamHeader{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.VisitorStream, VisitorConnectionID: "visitor-1", PublicURLID: ref.PublicURLID, PublishRunID: ref.PublishRunID, PublishRunNumber: ref.PublishRunNumber, PublisherConnectionID: ref.PublisherConnectionID, ConnectionAssignmentRevision: ref.ConnectionAssignmentRevision}
	for _, failed := range []bool{true, false} {
		result, done := make(chan error, 1), make(chan struct{})
		t.Cleanup(func() { cancel(); _ = relay.Close(); awaitPublisherTest(t, done) })
		go func() {
			defer close(done)
			stream, err := relay.OpenVisitorStream(ctx, h, tunnel.ReturnEvents{})
			if err == nil {
				_, err = io.Copy(io.Discard, stream)
				_ = stream.Close()
			}
			result <- err
		}()
		incoming, err := publisher.AcceptVisitorStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if failed {
			_ = incoming.Stream.Reset(17)
			if err := route.acceptVisitorForSession(ctx, incoming, live); err != nil {
				t.Fatal("acceptance failure would retire the publisher session", err)
			}
			if err := awaitPublisherTest(t, result); err == nil {
				t.Fatal("failed acceptance was acknowledged")
			}
			route.mu.Lock()
			remaining := len(route.streams)
			route.mu.Unlock()
			if remaining != 0 {
				t.Fatal("failed acceptance retained stream ownership")
			}
			route.handlers.Wait()
		} else {
			if err := incoming.Accept(); err != nil {
				t.Fatal(err)
			}
			if err := incoming.Stream.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if err := awaitPublisherTest(t, result); err != nil {
				t.Fatal("healthy sibling failed", err)
			}
			_ = incoming.Stream.Close()
		}
		awaitPublisherTest(t, done)
		if publisher.Err() != nil || relay.Err() != nil {
			t.Fatal("one stream failed its session")
		}
	}
}
