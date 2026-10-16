package tunnel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestClaimedPrivateTunnelRejectsAnotherRunOrSlotBeforeVisitorBytes(t *testing.T) {
	id := func(prefix string) string {
		value, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	ref := tunnelv1.PrivatePublisherConnectionRef{
		PrivateServiceID: id(opaqueid.PrivateServicePrefix), PrivateRunID: id(opaqueid.PrivateRunPrefix),
		RunNumber: 3, PublisherConnectionID: id(opaqueid.PublisherConnectionPrefix),
		ConnectionSlot: 0, ConnectionAssignmentRevision: 2, RelayServiceID: "relay-one",
	}
	client, server := newMemoryPair(t)
	ctx := tunnelContext(t)
	accepted := make(chan *Session, 1)
	go func() {
		session, _, err := Accept(ctx, server, func(_ context.Context, hello tunnelv1.Message) error {
			if hello.PrivateConnection == nil || *hello.PrivateConnection != ref || hello.PublisherConnection != nil {
				return errors.New("not a private publisher connection")
			}
			return nil
		})
		if err == nil {
			accepted <- session
		}
	}()
	publisher, err := Dial(ctx, client, tunnelv1.Message{ProtocolVersion: tunnelv1.Version, Type: tunnelv1.Hello,
		Role: tunnelv1.Publisher, Credential: "private-credential", PrivateConnection: &ref})
	if err != nil {
		t.Fatal(err)
	}
	relay := await(t, accepted)
	defer publisher.Close()
	defer relay.Close()
	header := tunnelv1.PrivateForwardingHeader{PrivateStreamHeader: tunnelv1.PrivateStreamHeader{
		ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.PrivateForwardingStream,
		PrivateServiceID: ref.PrivateServiceID, PrivateRunID: ref.PrivateRunID, RunNumber: ref.RunNumber,
		PublisherConnectionID: ref.PublisherConnectionID, ConnectionAssignmentRevision: ref.ConnectionAssignmentRevision,
		ConnectorSessionID: id(opaqueid.PrivateConnectorSessionPrefix), IdentityID: id(opaqueid.IdentityPrefix),
		SourceIP: "192.0.2.1", VisitorConnectionID: id(opaqueid.VisitorConnectionPrefix),
		TicketDigest: make([]byte, 32), Nonce: make([]byte, 32), ExpiresAt: time.Now().Add(time.Minute),
	}, ConnectionSlot: ref.ConnectionSlot, RelayServiceID: ref.RelayServiceID,
		RelayID: "relay-one-process", RelayRunID: id(opaqueid.RelayRunPrefix), RelayLeaseRevision: 2,
		LeaseExpiresAt: time.Now().Add(time.Minute)}
	for _, wrong := range []func(*tunnelv1.PrivateForwardingHeader){
		func(h *tunnelv1.PrivateForwardingHeader) { h.PrivateRunID = id(opaqueid.PrivateRunPrefix) },
		func(h *tunnelv1.PrivateForwardingHeader) { h.ConnectionSlot = 1 },
		func(h *tunnelv1.PrivateForwardingHeader) { h.ConnectionAssignmentRevision++ },
	} {
		stream, err := relay.transport.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		changed := header
		wrong(&changed)
		wrote := make(chan error, 1)
		go func() { wrote <- tunnelv1.WritePrivateForwardingHeader(stream, changed) }()
		type outcome struct {
			response tunnelv1.StreamResponse
			err      error
		}
		answered := make(chan outcome, 1)
		go func() { value, err := tunnelv1.ReadStreamResponse(stream); answered <- outcome{value, err} }()
		if _, err := publisher.AcceptPrivateForwardingStream(ctx); err == nil {
			t.Fatal("wrong private run reached publisher")
		}
		if err := <-wrote; err != nil {
			t.Fatal(err)
		}
		result := <-answered
		if result.err != nil || result.response.Type != tunnelv1.StreamRejected {
			t.Fatalf("wrong relay assignment was acknowledged: %+v %v", result.response, result.err)
		}
		_ = stream.Close()
	}
	stream, err := relay.transport.OpenStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	wrote := make(chan error, 1)
	go func() { wrote <- tunnelv1.WritePrivateForwardingHeader(stream, header) }()
	type outcome struct {
		response tunnelv1.StreamResponse
		err      error
	}
	answered := make(chan outcome, 1)
	go func() { value, err := tunnelv1.ReadStreamResponse(stream); answered <- outcome{value, err} }()
	incoming, err := publisher.AcceptPrivateForwardingStream(ctx)
	if err != nil || incoming.Header.PublisherConnectionID != ref.PublisherConnectionID {
		t.Fatalf("matching private stream was rejected: %v", err)
	}
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
	if err := incoming.Accept(); err != nil {
		t.Fatal(err)
	}
	result := <-answered
	if result.err != nil || result.response.Type != tunnelv1.StreamAccepted {
		t.Fatalf("matching private stream not acknowledged: %+v %v", result.response, result.err)
	}
}
