package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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

func TestConfirmedForwardingSendsVisitorBytesOnlyAfterRelayAcceptance(t *testing.T) {
	for _, accept := range []bool{false, true} {
		t.Run(map[bool]string{false: "rejected", true: "accepted"}[accept], func(t *testing.T) {
			client, server := newAuthenticatedPair(t)
			ctx := tunnelContext(t)
			opened := make(chan struct{})
			continueOpening := make(chan struct{})
			worker := tunnelWorker(t, func() { _ = server.Close() }, func() error {
				raw, err := server.transport.AcceptStream(ctx)
				if err != nil {
					return err
				}
				header, _, initial, err := tunnelv1.ReadForwardingOpening(raw)
				expected := internalForwardingHeader()
				expected.ConfirmBeforeBytes = true
				if err != nil || header != expected || string(initial) != "proxy metadata" {
					return errors.New("relay received visitor bytes before accepting the new session")
				}
				close(opened)
				<-continueOpening
				reply := newReplyStream(raw, initial)
				if !accept {
					return reply.respond(tunnelv1.StreamResponse{Type: tunnelv1.StreamRejected, Code: tunnelv1.StaleConnectionAssignment})
				}
				if err := reply.respond(tunnelv1.StreamResponse{Type: tunnelv1.StreamAccepted}); err != nil {
					return err
				}
				if err := reply.sendAccepted(); err != nil {
					return err
				}
				bytes := make([]byte, len("proxy metadataclient hello"))
				if _, err := io.ReadFull(reply, bytes); err != nil || string(bytes) != "proxy metadataclient hello" {
					return errors.New("relay lost confirmed visitor bytes")
				}
				return nil
			})
			type openedStream struct {
				stream net.Conn
				err    error
			}
			result := make(chan openedStream, 1)
			go func() {
				stream, err := client.StartConfirmedInternalForwardingStream(ctx, internalForwardingHeader(), []byte("proxy metadata"), []byte("client hello"), nil)
				result <- openedStream{stream: stream, err: err}
			}()
			<-opened
			select {
			case <-result:
				t.Fatal("forwarder returned before relay acceptance")
			default:
			}
			close(continueOpening)
			got := <-result
			if accept {
				if got.err != nil {
					t.Fatal(got.err)
				}
				_ = got.stream.Close()
			} else {
				var rejected *ProtocolError
				var opening *OpeningError
				if !errors.As(got.err, &opening) || opening.Committed || !errors.As(got.err, &rejected) || rejected.Code != tunnelv1.StaleConnectionAssignment {
					t.Fatalf("rejection crossed retry boundary: %v", got.err)
				}
			}
			if err := await(t, worker); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestConfirmedForwardingBoundsBackpressuredBytesAfterAcceptance(t *testing.T) {
	client, server := newAuthenticatedPair(t)
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	worker := tunnelWorker(t, func() { unblock(); _ = server.Close() }, func() error {
		raw, err := server.transport.AcceptStream(tunnelContext(t))
		if err != nil {
			return err
		}
		defer raw.Close()
		_, _, initial, err := tunnelv1.ReadForwardingOpening(raw)
		if err != nil || string(initial) != "proxy metadata" {
			return errors.New("relay did not receive the metadata-only opening")
		}
		reply := newReplyStream(raw, initial)
		if err := reply.respond(tunnelv1.StreamResponse{Type: tunnelv1.StreamAccepted}); err != nil {
			return err
		}
		if err := reply.sendAccepted(); err != nil {
			return err
		}
		// leave the initial-byte write backpressured after acceptance.
		<-release
		return nil
	})
	t.Cleanup(unblock)
	result := make(chan error, 1)
	go func() {
		_, err := client.StartConfirmedInternalForwardingStream(ctx, internalForwardingHeader(), []byte("proxy metadata"), []byte("client hello"), nil)
		result <- err
	}()
	select {
	case err := <-result:
		var opening *OpeningError
		var timeout net.Error
		if !errors.As(err, &opening) || opening.Committed || !errors.Is(err, context.DeadlineExceeded) && (!errors.As(err, &timeout) || !timeout.Timeout()) {
			t.Fatalf("blocked pre-byte write escaped setup deadline: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("confirmed opening ignored cancellation after relay acceptance")
	}
	unblock()
	if err := await(t, worker); err != nil {
		t.Fatal(err)
	}
}

func TestConfirmedVisitorOpeningWaitsForPublisherAdmission(t *testing.T) {
	for _, accept := range []bool{false, true} {
		t.Run(map[bool]string{false: "rejected", true: "accepted"}[accept], func(t *testing.T) {
			client, server := newAuthenticatedPair(t)
			ctx := tunnelContext(t)
			opened := make(chan struct{})
			continueOpening := make(chan struct{})
			worker := tunnelWorker(t, func() { _ = server.Close() }, func() error {
				incoming, err := server.AcceptVisitorStream(ctx)
				if err != nil {
					return err
				}
				if initial := incoming.response.stream.takeInitial(); len(initial) != 0 {
					return errors.New("publisher received visitor bytes before admission")
				}
				if !incoming.Header.ConfirmBeforeBytes {
					return errors.New("publisher did not receive confirmation request")
				}
				close(opened)
				<-continueOpening
				if !accept {
					return incoming.Reject(tunnelv1.Unauthenticated)
				}
				if err := incoming.Accept(); err != nil {
					return err
				}
				defer incoming.Stream.Close()
				byteReceived := make([]byte, len("client hello"))
				if _, err := io.ReadFull(incoming.Stream, byteReceived); err != nil || string(byteReceived) != "client hello" {
					return errors.New("publisher lost visitor bytes after admission")
				}
				return nil
			})
			type openedStream struct {
				stream net.Conn
				err    error
			}
			result := make(chan openedStream, 1)
			go func() {
				stream, err := client.StartConfirmedVisitorStream(ctx, visitorStreamHeader(), nil)
				result <- openedStream{stream: stream, err: err}
			}()
			<-opened
			select {
			case <-result:
				t.Fatal("relay acknowledged visitor before publisher admission")
			default:
			}
			close(continueOpening)
			got := <-result
			if accept {
				if got.err != nil {
					t.Fatal(got.err)
				}
				if _, err := got.stream.Write([]byte("client hello")); err != nil {
					t.Fatal(err)
				}
				_ = got.stream.Close()
			} else {
				var opening *OpeningError
				var rejected *ProtocolError
				if !errors.As(got.err, &opening) || opening.Committed || !errors.As(got.err, &rejected) || rejected.Code != tunnelv1.Unauthenticated {
					t.Fatalf("publisher rejection crossed retry boundary: %v", got.err)
				}
			}
			if err := await(t, worker); err != nil {
				t.Fatal(err)
			}
		})
	}
}
