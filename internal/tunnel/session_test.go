package tunnel

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestSessionHandshakeAndVisitorStream(t *testing.T) {
	clientTransport, serverTransport := newMemoryPair(t)
	ctx := tunnelContext(t)
	type accepted struct {
		session *Session
		hello   tunnelv1.Message
		err     error
	}
	result := tunnelWorker(t, func() { _ = serverTransport.Close() }, func() accepted {
		s, h, err := Accept(ctx, serverTransport, func(_ context.Context, m tunnelv1.Message) error {
			if m.Credential != "credential" {
				return &ProtocolError{Code: tunnelv1.Unauthenticated}
			}
			return nil
		})
		return accepted{s, h, err}
	})
	client, err := Dial(ctx, clientTransport, publisherHello())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	server := await(t, result)
	if server.err != nil {
		t.Fatal(server.err)
	}
	t.Cleanup(func() { _ = server.session.Close() })
	if server.hello.Credential != "credential" || server.hello.PublisherConnection == nil || *server.hello.PublisherConnection != *publisherHello().PublisherConnection {
		t.Fatalf("hello=%+v", server.hello)
	}
	header := visitorStreamHeader()
	route := tunnelWorker(t, func() { _ = server.session.Close() }, func() error {
		incoming, err := server.session.AcceptVisitorStream(ctx)
		if err != nil {
			return err
		}
		defer incoming.Stream.Close()
		if incoming.Header != header {
			return errors.New("unexpected publisher header")
		}
		if err := incoming.Accept(); err != nil {
			return err
		}
		payload, err := io.ReadAll(io.LimitReader(incoming.Stream, 7))
		if err == nil && string(payload) != "payload" {
			err = errors.New("unexpected payload")
		}
		return err
	})
	stream, err := client.OpenVisitorStream(ctx, header)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	if _, err := stream.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := await(t, route); err != nil {
		t.Fatal(err)
	}
}

func TestSessionRejectsHello(t *testing.T) {
	a, b := newMemoryPair(t)
	ctx := tunnelContext(t)
	cause := errors.New("claim failed")
	result := tunnelWorker(t, func() { _ = b.Close() }, func() error {
		_, _, err := Accept(ctx, b, func(context.Context, tunnelv1.Message) error {
			return errors.Join(cause, &ProtocolError{Code: tunnelv1.StaleConnectionAssignment})
		})
		return err
	})
	_, peerErr := Dial(ctx, a, publisherHello())
	localErr := await(t, result)
	for _, err := range []error{peerErr, localErr} {
		var p *ProtocolError
		if !errors.As(err, &p) || p.Code != tunnelv1.StaleConnectionAssignment {
			t.Fatalf("handshake=%v", err)
		}
	}
	if errors.Is(peerErr, cause) || !errors.Is(localErr, cause) {
		t.Fatalf("claim cause leaked to peer or was lost locally: peer=%v local=%v", peerErr, localErr)
	}
}

func TestVisitorStreamRejection(t *testing.T) {
	client, server := newAuthenticatedPair(t)
	ctx := tunnelContext(t)
	done := tunnelWorker(t, func() { _ = server.Close() }, func() error {
		incoming, err := server.AcceptVisitorStream(ctx)
		if err != nil {
			return err
		}
		defer incoming.Stream.Close()
		return incoming.Reject(tunnelv1.StalePublishRunNumber)
	})
	_, err := client.OpenVisitorStream(ctx, visitorStreamHeader())
	var p *ProtocolError
	if !errors.As(err, &p) || p.Code != tunnelv1.StalePublishRunNumber {
		t.Fatalf("open=%v", err)
	}
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestInternalForwardingStream(t *testing.T) {
	client, server := newAuthenticatedPair(t)
	ctx := tunnelContext(t)
	header := internalForwardingHeader()
	done := tunnelWorker(t, func() { _ = server.Close() }, func() error {
		incoming, err := server.AcceptInternalForwardingStream(ctx)
		if err != nil {
			return err
		}
		defer incoming.Stream.Close()
		if incoming.Header != header {
			return errors.New("unexpected internal forwarding header")
		}
		if err := incoming.Accept(); err != nil {
			return err
		}
		payload, err := io.ReadAll(io.LimitReader(incoming.Stream, 7))
		if err == nil && string(payload) != "payload" {
			err = errors.New("unexpected payload")
		}
		return err
	})
	stream, err := client.OpenInternalForwardingStream(ctx, header)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	if _, err := stream.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestAdmissionUsesSeparateAuthenticatedStreamsAndAcknowledgement(t *testing.T) {
	client, server := newAuthenticatedPair(t)
	ctx := tunnelContext(t)
	publisher := tunnelv1.AdmissionHeader{
		ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.PublisherAdmissionStream,
		VisitorConnectionID: "visitor_1", PublicURLID: "url_1", PublishRunID: "run_1", PublishRunNumber: 2,
		PublisherConnectionID: "connection_1", ConnectionAssignmentRevision: 3, RelayServiceID: "service_1",
	}
	respond := tunnelWorker(t, func() { _ = server.Close() }, func() error {
		incoming, err := server.AcceptPublisherAdmissionStream(ctx)
		if err != nil {
			return err
		}
		defer incoming.Stream.Close()
		if incoming.Header != publisher {
			return errors.New("publisher admission header changed")
		}
		if err := incoming.Accept(); err != nil {
			return err
		}
		return tunnelv1.WriteAdmissionResult(incoming.Stream, tunnelv1.AdmissionResult{Type: tunnelv1.StreamRejected, Code: tunnelv1.CapacityExceeded})
	})
	stream, err := client.OpenPublisherAdmissionStream(ctx, publisher)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if result, err := tunnelv1.ReadAdmissionResult(stream); err != nil || result.Type != tunnelv1.StreamRejected || result.Code != tunnelv1.CapacityExceeded {
		t.Fatalf("relay decision = %+v, %v", result, err)
	}
	if err := await(t, respond); err != nil {
		t.Fatal(err)
	}
	ingress := publisher
	ingress.Kind, ingress.RelayID, ingress.RelayRunID, ingress.RelayLeaseRevision = tunnelv1.IngressAdmissionStream, "relay_1", "relay_run_1", 4
	forward := tunnelWorker(t, func() { _ = client.Close() }, func() error {
		incoming, err := client.AcceptIngressAdmissionStream(ctx)
		if err != nil {
			return err
		}
		defer incoming.Stream.Close()
		if incoming.Header != ingress {
			return errors.New("ingress admission header changed")
		}
		if err := incoming.Accept(); err != nil {
			return err
		}
		return tunnelv1.WriteAdmissionResult(incoming.Stream, tunnelv1.AdmissionResult{Type: tunnelv1.StreamAccepted})
	})
	back, err := server.OpenIngressAdmissionStream(ctx, ingress)
	if err != nil {
		t.Fatal(err)
	}
	defer back.Close()
	if result, err := tunnelv1.ReadAdmissionResult(back); err != nil || result.Type != tunnelv1.StreamAccepted {
		t.Fatalf("ingress acknowledgement = %+v, %v", result, err)
	}
	if err := await(t, forward); err != nil {
		t.Fatal(err)
	}
}

func TestAdmissionRejectsWrongStreamDirection(t *testing.T) {
	client, server := newAuthenticatedPair(t)
	ctx := tunnelContext(t)
	header := tunnelv1.AdmissionHeader{
		ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.IngressAdmissionStream,
		VisitorConnectionID: "visitor_1", PublicURLID: "url_1", PublishRunID: "run_1", PublishRunNumber: 2,
		PublisherConnectionID: "connection_1", ConnectionAssignmentRevision: 3, RelayServiceID: "service_1",
		RelayID: "relay_1", RelayRunID: "relay_run_1", RelayLeaseRevision: 4,
	}
	serverError := tunnelWorker(t, func() { _ = server.Close() }, func() error {
		_, err := server.AcceptPublisherAdmissionStream(ctx)
		return err
	})
	_, err := client.OpenIngressAdmissionStream(ctx, header)
	var protocol *ProtocolError
	if !errors.As(err, &protocol) || protocol.Code != tunnelv1.InvalidMessage {
		t.Fatalf("wrong-direction admission stream = %v", err)
	}
	var headerError *StreamHeaderError
	if err := await(t, serverError); !errors.As(err, &headerError) {
		t.Fatalf("relay did not isolate malformed sideband: %v", err)
	}
}
