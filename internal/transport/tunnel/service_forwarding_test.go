package tunnel

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
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
	ref := tunnelv1.ServicePublisherConnectionRef{
		ServiceID: id(opaqueid.ServicePrefix), ServiceRunID: id(opaqueid.ServiceRunPrefix),
		RunNumber: 3, PublisherConnectionID: id(opaqueid.PublisherConnectionPrefix),
		ConnectionSlot: 0, ConnectionAssignmentRevision: 2, RelayServiceID: "relay-one",
	}
	client, server := newMemoryPair(t)
	ctx := tunnelContext(t)
	accepted := make(chan *Session, 1)
	go func() {
		session, _, err := Accept(ctx, server, func(_ context.Context, hello tunnelv1.Message) error {
			if hello.ServiceConnection == nil || *hello.ServiceConnection != ref {
				return errors.New("not a private publisher connection")
			}
			return nil
		})
		if err == nil {
			accepted <- session
		}
	}()
	publisher, err := Dial(ctx, client, tunnelv1.Message{ProtocolVersion: tunnelv1.Version, Type: tunnelv1.Hello,
		Role: tunnelv1.Publisher, Credential: "private-credential", ServiceConnection: &ref})
	if err != nil {
		t.Fatal(err)
	}
	relay := await(t, accepted)
	defer publisher.Close()
	defer relay.Close()
	if borrowed, err := publisher.BorrowServicePublisherTransport(); err != nil || borrowed != client {
		t.Fatal("claimed publisher did not borrow its exact transport", err)
	}
	header := tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{
		ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream,
		ServiceID: ref.ServiceID, ServiceRunID: ref.ServiceRunID, RunNumber: ref.RunNumber,
		PublisherConnectionID: ref.PublisherConnectionID, ConnectionAssignmentRevision: ref.ConnectionAssignmentRevision,
		PublicService: &tunnelv1.PublicServiceAdmission{IngressID: "ingress-a", IngressRunID: id(opaqueid.IngressRunPrefix), IngressLeaseRevision: 1, DestinationPort: 25443},
		SourceIP:      "192.0.2.1", VisitorConnectionID: id(opaqueid.VisitorConnectionPrefix),
		ExpiresAt: time.Now().Add(time.Minute),
	}, ConnectionSlot: ref.ConnectionSlot, RelayServiceID: ref.RelayServiceID,
		RelayID: "relay-one-process", RelayRunID: id(opaqueid.RelayRunPrefix), RelayLeaseRevision: 2,
		ServingUntil: time.Now().Add(time.Minute)}
	for _, wrong := range []func(*tunnelv1.ServiceForwardingHeader){
		func(h *tunnelv1.ServiceForwardingHeader) { h.ServiceID = id(opaqueid.ServicePrefix) },
		func(h *tunnelv1.ServiceForwardingHeader) { h.ServiceRunID = id(opaqueid.ServiceRunPrefix) },
		func(h *tunnelv1.ServiceForwardingHeader) { h.RunNumber++ },
		func(h *tunnelv1.ServiceForwardingHeader) {
			h.PublisherConnectionID = id(opaqueid.PublisherConnectionPrefix)
		},
		func(h *tunnelv1.ServiceForwardingHeader) { h.ConnectionSlot = 1 },
		func(h *tunnelv1.ServiceForwardingHeader) { h.ConnectionAssignmentRevision++ },
		func(h *tunnelv1.ServiceForwardingHeader) { h.RelayServiceID = "another-relay" },
	} {
		stream, err := relay.transport.OpenStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		changed := header
		wrong(&changed)
		wrote := make(chan error, 1)
		go func() { wrote <- tunnelv1.WriteServiceForwardingHeader(stream, changed) }()
		type outcome struct {
			response tunnelv1.ReturnFrame
			err      error
		}
		answered := make(chan outcome, 1)
		go func() { value, err := tunnelv1.ReadReturnFrame(stream); answered <- outcome{value, err} }()
		if _, err := publisher.AcceptServiceForwardingStream(ctx); err == nil {
			t.Fatal("wrong private run reached publisher")
		}
		if err := <-wrote; err != nil {
			t.Fatal(err)
		}
		result := <-answered
		if result.err != nil || result.response.Kind != tunnelv1.ReturnRejected {
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
	go func() { _, err := tunnelv1.WriteServiceOpening(stream, header); wrote <- err }()
	type outcome struct {
		response tunnelv1.ReturnFrame
		err      error
	}
	answered := make(chan outcome, 1)
	go func() { value, err := tunnelv1.ReadReturnFrame(stream); answered <- outcome{value, err} }()
	incoming, err := publisher.AcceptServiceForwardingStream(ctx)
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
	if result.err != nil || result.response.Kind != tunnelv1.ReturnAccepted {
		t.Fatalf("matching private stream not acknowledged: %+v %v", result.response, result.err)
	}
}

func TestServicePublisherTransportRequiresClaimedPublisherRole(t *testing.T) {
	client, _ := newMemoryPair(t)
	for _, session := range []*Session{nil, {}, {transport: client}, {transport: client, role: tunnelv1.Publisher},
		{transport: client, role: tunnelv1.Connector, serviceConnection: &tunnelv1.ServicePublisherConnectionRef{}}} {
		borrowed, err := session.BorrowServicePublisherTransport()
		var rejected *ProtocolError
		if borrowed != nil || !errors.As(err, &rejected) || rejected.Code != tunnelv1.Unauthenticated {
			t.Fatal("unclaimed or wrong-role session lent its transport", err)
		}
	}
}

func TestServiceForwardingAcceptsIngressWithoutBorrowingPublisherIdentity(t *testing.T) {
	ingress, relay := newHeaderBoundsPair(t, ingressBoundsHello())
	ctx := tunnelContext(t)
	header := maximumServiceHeader("relay-a")
	type opened struct {
		stream io.ReadWriteCloser
		err    error
	}
	result := tunnelWorker(t, func() { _ = ingress.Close() }, func() opened {
		stream, err := ingress.OpenServiceForwardingStream(ctx, header)
		return opened{stream, err}
	})
	incoming, err := relay.AcceptServiceForwardingStream(ctx)
	if err != nil || incoming.Header.ServiceID != header.ServiceID || incoming.Header.ServiceRunID != header.ServiceRunID {
		t.Fatal("ingress forwarding was mistaken for a claimed publisher", err)
	}
	defer incoming.Stream().Close()
	if err := incoming.Accept(); err != nil {
		t.Fatal(err)
	}
	stream := await(t, result)
	if stream.err != nil {
		t.Fatal(stream.err)
	}
	defer stream.stream.Close()
	write := tunnelWorker(t, func() { _ = stream.stream.Close() }, func() error {
		_, err := io.WriteString(stream.stream, "visitor bytes")
		return err
	})
	payload := make([]byte, len("visitor bytes"))
	if _, err := io.ReadFull(incoming.Stream(), payload); err != nil || string(payload) != "visitor bytes" {
		t.Fatal("service forwarding changed visitor bytes", err)
	}
	if err := await(t, write); err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []*Session{nil, {}, {role: tunnelv1.Publisher}, {role: tunnelv1.Connector}} {
		if _, err := wrong.AcceptServiceForwardingStream(ctx); err == nil {
			t.Fatal("unclaimed or unrelated peer accepted service forwarding")
		}
	}
}
