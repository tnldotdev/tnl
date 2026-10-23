package tunnel

import (
	"bytes"
	"errors"
	"io"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestOpeningReturnsBeforeAcceptanceAndOrdersPromotionWithBytes(t *testing.T) {
	client, server := newAuthenticatedPair(t)
	ctx := tunnelContext(t)
	allowAccept := make(chan struct{})
	initial := []byte("PROXY and opaque ClientHello")
	h := visitorStreamHeader()
	promotion := tunnelv1.AdmissionHeader{ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.PublisherAdmissionStream, VisitorConnectionID: h.VisitorConnectionID,
		PublicURLID: h.PublicURLID, PublishRunID: h.PublishRunID, PublishRunNumber: h.PublishRunNumber, PublisherConnectionID: h.PublisherConnectionID,
		ConnectionAssignmentRevision: h.ConnectionAssignmentRevision, RelayServiceID: "relay"}
	worker := tunnelWorker(t, func() { _ = server.Close() }, func() error {
		raw, err := server.transport.AcceptStream(ctx)
		if err != nil {
			return err
		}
		got, first, err := tunnelv1.ReadVisitorOpening(raw)
		if err != nil || got != h || !bytes.Equal(first, initial) {
			return errors.New("opening changed visitor bytes or identity")
		}
		select {
		case <-allowAccept:
		case <-ctx.Done():
			return ctx.Err()
		}
		reply := newReplyStream(raw, first)
		defer reply.Close()
		if err := reply.respond(tunnelv1.StreamResponse{Type: tunnelv1.StreamAccepted}); err != nil {
			return err
		}
		request := make([]byte, len(initial)+4)
		if _, err := io.ReadFull(reply, request); err != nil || string(request) != string(initial)+"more" {
			return errors.New("request write depended on reading acceptance")
		}
		if _, err := reply.Write([]byte("TLS hello")); err != nil {
			return err
		}
		if err := reply.Promote(promotion); err != nil {
			return err
		}
		if _, err := reply.Write([]byte("HTTP response")); err != nil {
			return err
		}
		return reply.CloseWrite()
	})
	var notified atomic.Int64
	stream, err := client.StartVisitorStream(ctx, h, initial, &ReturnEvents{Promoted: func(got tunnelv1.AdmissionHeader) error {
		if got != promotion {
			return errors.New("promotion changed visitor identity")
		}
		notified.Add(1)
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	close(allowAccept)
	if _, err := stream.Write([]byte("more")); err != nil {
		t.Fatal(err)
	}
	hello := make([]byte, len("TLS hello"))
	if _, err := io.ReadFull(stream, hello); err != nil || string(hello) != "TLS hello" || notified.Load() != 0 {
		t.Fatal("outer framing entered TLS or promotion overtook earlier bytes", err)
	}
	response, err := io.ReadAll(stream)
	if err != nil || string(response) != "HTTP response" || notified.Load() != 1 {
		t.Fatal("application response overtook its one-way promotion", err)
	}
	if err := await(t, worker); err != nil {
		t.Fatal(err)
	}
}

func TestOpeningRejectionNeverReachesVisitorTLS(t *testing.T) {
	client, server := newAuthenticatedPair(t)
	ctx := tunnelContext(t)
	worker := tunnelWorker(t, func() { _ = server.Close() }, func() error {
		raw, err := server.transport.AcceptStream(ctx)
		if err != nil {
			return err
		}
		_, initial, err := tunnelv1.ReadVisitorOpening(raw)
		if err != nil {
			return err
		}
		return newReplyStream(raw, initial).respond(tunnelv1.StreamResponse{Type: tunnelv1.StreamRejected, Code: tunnelv1.CapacityExceeded})
	})
	stream, err := client.StartVisitorStream(ctx, visitorStreamHeader(), []byte("hello"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	buffer := make([]byte, 256)
	n, err := stream.Read(buffer)
	var rejected *ProtocolError
	if n != 0 || !errors.As(err, &rejected) || rejected.Code != tunnelv1.CapacityExceeded {
		t.Fatal("rejection framing leaked into visitor bytes", n, err)
	}
	if err := await(t, worker); err != nil {
		t.Fatal(err)
	}
}
