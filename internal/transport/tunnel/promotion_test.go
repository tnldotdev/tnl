package tunnel

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestStreamLocalPromotionOrdersBytesAndRejectsReuse(t *testing.T) {
	client, server := newAuthenticatedPair(t)
	ctx := tunnelContext(t)
	h := visitorStreamHeader()
	h.AccessPending = true
	promoted := false
	worker := tunnelWorker(t, func() { _ = server.Close() }, func() error {
		incoming, err := server.AcceptVisitorStream(ctx)
		if err != nil {
			return err
		}
		defer incoming.Stream.Close()
		if err := incoming.Accept(); err != nil {
			return err
		}
		// connection wrappers and caller-owned header copies cannot replace the
		// incoming request's immutable promotion responder or identity.
		incoming.Stream = &promotionWriteSignal{Stream: incoming.Stream, entered: make(chan struct{})}
		incoming.Header.VisitorConnectionID = "untrusted-copy"
		if _, err := incoming.Stream.Write([]byte("TLS")); err != nil {
			return err
		}
		if err := incoming.Promote(ctx); err != nil {
			return err
		}
		if err := incoming.Promote(ctx); !errors.Is(err, tunnelv1.ErrReturnFrame) {
			return errors.New("promotion reused")
		}
		if _, err := incoming.Stream.Write([]byte("HTTP")); err != nil {
			return err
		}
		return incoming.Stream.CloseWrite()
	})
	stream, err := client.OpenVisitorStream(ctx, h, ReturnEvents{Promoted: func(p tunnelv1.AdmissionHeader) error {
		if p.VisitorConnectionID != h.VisitorConnectionID || p.PublisherConnectionID != h.PublisherConnectionID || p.ConnectionAssignmentRevision != h.ConnectionAssignmentRevision {
			return errors.New("promotion changed identity")
		}
		promoted = true
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	var hello [3]byte
	if _, err := io.ReadFull(stream, hello[:]); err != nil || string(hello[:]) != "TLS" || promoted {
		t.Fatal("promotion overtook TLS", err)
	}
	data, err := io.ReadAll(stream)
	if err != nil || string(data) != "HTTP" || !promoted {
		t.Fatal("framing entered visitor bytes", err)
	}
	if err := await(t, worker); err != nil {
		t.Fatal(err)
	}
}

func TestPromotionCancellationInterruptsBlockedReturnWrite(t *testing.T) {
	client, server := newAuthenticatedPair(t)
	h := visitorStreamHeader()
	h.AccessPending = true
	incoming := make(chan *IncomingVisitorStream, 1)
	worker := tunnelWorker(t, func() { _ = server.Close() }, func() error {
		v, err := server.AcceptVisitorStream(tunnelContext(t))
		if err != nil {
			return err
		}
		incoming <- v
		return v.Accept()
	})
	stream, err := client.OpenVisitorStream(tunnelContext(t), h, ReturnEvents{})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	v := await(t, incoming)
	defer v.Stream.Close()
	if err := await(t, worker); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	if err := v.Promote(ctx); !errors.Is(err, context.DeadlineExceeded) {
		var timeout interface{ Timeout() bool }
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatal("blocked promotion ignored cancellation", err)
		}
	}
	if client.Err() != nil || server.Err() != nil {
		t.Fatal("one promotion retired the session")
	}
}
