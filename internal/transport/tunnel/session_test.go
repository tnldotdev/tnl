package tunnel

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
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
	stream, err := client.OpenVisitorStream(ctx, header, nil, ReturnEvents{})
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

// the pipe fixture exposes writes to the reader before its writer returns.
// wait for server deadline cleanup before the client deliberately closes it.
type handshakeCloseBarrier struct {
	muxsession.Session
	completed <-chan struct{}
	ctx       context.Context
}

func (s handshakeCloseBarrier) Close() error {
	select {
	case <-s.completed:
	case <-s.ctx.Done():
	}
	return s.Session.Close()
}

func TestConnectorHelloReceiptRequiredAndBoundToPreparedDelivery(t *testing.T) {
	proof := tunnelv1.ConnectorPairLegProof{PairID: "cpp_1234567890123456789012", DeliveryGeneration: 1,
		ServiceID: "svc_1234567890123456789012", ServiceRunID: "srun_1234567890123456789012", RunNumber: 1,
		PublisherIdentityID: "pub_1234567890123456789012", PublisherConnectionID: "pc_1234567890123456789012",
		AssignmentRevision: 1, RelayServiceID: "relay-a", RelayID: "node-a", RelayRunID: "run-a", RelayLeaseRevision: 1,
		RequestedAt: time.Now(), Nonce: make([]byte, 32), Signature: make([]byte, 64)}
	hello := tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Connector, ConnectorPairLegProof: &proof}
	id := "AQEBAQEBAQEBAQEBAQEBAQ"
	receipt := tunnelv1.ConnectorPairLegAccepted{PairID: proof.PairID, DeliveryID: id, DeliveryGeneration: 1, ConnectionSlot: 0,
		SourceIP: "127.0.0.1", ObservedAt: time.Now().UTC().Truncate(time.Microsecond), ExpiresAt: time.Now().Add(time.Minute).UTC().Truncate(time.Microsecond)}
	for _, test := range []struct {
		name     string
		response *tunnelv1.ConnectorPairLegAccepted
		expected string
		ok       bool
		serverOK bool
	}{
		{"accepted", &receipt, id, true, true},
		{"missing receipt", nil, id, false, false},
		{"wrong prepared delivery", &receipt, "AgICAgICAgICAgICAgICAg", false, true},
		{"wrong signed slot", &tunnelv1.ConnectorPairLegAccepted{PairID: receipt.PairID, DeliveryID: id, DeliveryGeneration: 1, ConnectionSlot: 1, SourceIP: receipt.SourceIP, ObservedAt: receipt.ObservedAt, ExpiresAt: receipt.ExpiresAt}, id, false, false},
		{"expired receipt", &tunnelv1.ConnectorPairLegAccepted{PairID: receipt.PairID, DeliveryID: id, DeliveryGeneration: 1, ConnectionSlot: 0, SourceIP: receipt.SourceIP, ObservedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(-time.Second)}, id, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, server := newMemoryPair(t)
			ctx := tunnelContext(t)
			handshakeDone := make(chan struct{})
			done := tunnelWorker(t, func() { _ = server.Close() }, func() error {
				s, _, err := AcceptWithResult(ctx, server, func(context.Context, tunnelv1.Message) (*tunnelv1.ConnectorPairLegAccepted, error) {
					return test.response, nil
				})
				close(handshakeDone)
				if s != nil {
					if incoming, streamErr := s.AcceptVisitorStream(ctx); streamErr == nil || incoming != nil {
						return errors.New("connector receipt admitted a visitor stream without a peer owner")
					}
					<-s.Done()
				}
				return err
			})
			s, got, err := DialConnector(ctx, handshakeCloseBarrier{Session: client, completed: handshakeDone, ctx: ctx}, hello, test.expected)
			if (err == nil) != test.ok || test.ok && got != receipt {
				t.Fatalf("native handshake: receipt=%+v err=%v", got, err)
			}
			if s != nil {
				_ = s.Close()
			}
			if err := await(t, done); (err == nil) != test.serverOK {
				t.Fatalf("server handshake: %v", err)
			}
		})
	}
	client, _ := newMemoryPair(t)
	if s, err := Dial(t.Context(), client, hello); err == nil || s != nil {
		t.Fatal("generic dial accepted connector hello without an expected delivery")
	}
}

func TestPublisherAndIngressRejectConnectorHelloReceipt(t *testing.T) {
	for _, hello := range []tunnelv1.Message{publisherHello(), {Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version, Role: tunnelv1.Ingress, Credential: "secret"}} {
		t.Run(string(hello.Role), func(t *testing.T) {
			client, server := newMemoryPair(t)
			ctx := tunnelContext(t)
			done := tunnelWorker(t, func() { _ = server.Close() }, func() error {
				stream, err := server.AcceptStream(ctx)
				if err != nil {
					return err
				}
				if _, err := tunnelv1.ReadControl(stream); err != nil {
					return err
				}
				return tunnelv1.WriteControl(stream, tunnelv1.Message{Type: tunnelv1.HelloAccepted, ProtocolVersion: tunnelv1.Version,
					ConnectorPairLegAccepted: &tunnelv1.ConnectorPairLegAccepted{PairID: "cpp_1234567890123456789012",
						DeliveryID: "AQEBAQEBAQEBAQEBAQEBAQ", DeliveryGeneration: 1, ConnectionSlot: 0,
						SourceIP: "127.0.0.1", ObservedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}})
			})
			if s, err := Dial(ctx, client, hello); err == nil || s != nil {
				t.Fatal("another role accepted a connector receipt")
			}
			if err := await(t, done); err != nil {
				t.Fatal(err)
			}
		})
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
	_, err := client.OpenVisitorStream(ctx, visitorStreamHeader(), nil, ReturnEvents{})
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
		defer incoming.Stream().Close()
		request, ok := incoming.(*IncomingPublicForwardingStream)
		if !ok || request.Header != header {
			return errors.New("unexpected internal forwarding header")
		}
		if err := incoming.Accept(); err != nil {
			return err
		}
		payload, err := io.ReadAll(io.LimitReader(incoming.Stream(), 7))
		if err == nil && string(payload) != "payload" {
			err = errors.New("unexpected payload")
		}
		return err
	})
	stream, err := client.OpenInternalForwardingStream(ctx, header, nil, nil, ReturnEvents{})
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
