package tunnel

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestSessionHandshakeAndPublisherStream(t *testing.T) {
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
	header := publisherStreamHeader()
	route := tunnelWorker(t, func() { _ = server.session.Close() }, func() error {
		incoming, err := server.session.AcceptPublisherStream(ctx)
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
	stream, err := client.OpenPublisherStream(ctx, header)
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
	result := tunnelWorker(t, func() { _ = b.Close() }, func() error {
		_, _, err := Accept(ctx, b, func(context.Context, tunnelv1.Message) error {
			return &ProtocolError{Code: tunnelv1.StaleConnectionAssignment}
		})
		return err
	})
	_, err := Dial(ctx, a, publisherHello())
	for _, err := range []error{err, await(t, result)} {
		var p *ProtocolError
		if !errors.As(err, &p) || p.Code != tunnelv1.StaleConnectionAssignment {
			t.Fatalf("handshake=%v", err)
		}
	}
}

func TestPublisherStreamRejection(t *testing.T) {
	client, server := newAuthenticatedPair(t)
	ctx := tunnelContext(t)
	done := tunnelWorker(t, func() { _ = server.Close() }, func() error {
		incoming, err := server.AcceptPublisherStream(ctx)
		if err != nil {
			return err
		}
		defer incoming.Stream.Close()
		return incoming.Reject(tunnelv1.StaleRouteVersion)
	})
	_, err := client.OpenPublisherStream(ctx, publisherStreamHeader())
	var p *ProtocolError
	if !errors.As(err, &p) || p.Code != tunnelv1.StaleRouteVersion {
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
