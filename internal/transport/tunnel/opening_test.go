package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestOpeningPipelinesPrefixBeforeAcceptance(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(map[bool]string{false: "server_first", true: "late_rejection"}[reject], func(t *testing.T) {
			client, server := newAuthenticatedPair(t)
			h := visitorStreamHeader()
			h.ConfirmBeforeBytes = false
			incoming := tunnelWorker(t, func() { _ = server.Close() }, func() *IncomingVisitorStream {
				v, err := server.AcceptVisitorStream(tunnelContext(t))
				if err != nil {
					t.Error(err)
				}
				return v
			})
			stream, err := client.OpenVisitorStream(tunnelContext(t), h, []byte("initial"), ReturnEvents{})
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			v := await(t, incoming)
			if v == nil {
				t.Fatal("missing incoming stream")
			}
			defer v.Stream.Close()
			var initial [7]byte
			if _, err := io.ReadFull(v.Stream, initial[:]); err != nil || string(initial[:]) != "initial" {
				t.Fatal("prefix needed acceptance", err)
			}
			worker := tunnelWorker(t, func() { _ = server.Close() }, func() error {
				if reject {
					return v.Reject(tunnelv1.Unavailable)
				}
				if err := v.Accept(); err != nil {
					return err
				}
				if _, err := v.Stream.Write([]byte("greeting")); err != nil {
					return err
				}
				return v.Stream.CloseWrite()
			})
			data, err := io.ReadAll(stream)
			if reject {
				var p *ProtocolError
				if !errors.As(err, &p) || p.Code != tunnelv1.Unavailable || len(data) != 0 {
					t.Fatalf("late rejection: %q, %v", data, err)
				}
			} else if err != nil || string(data) != "greeting" {
				t.Fatalf("server-first reply: %q, %v", data, err)
			}
			if err := await(t, worker); err != nil {
				t.Fatal(err)
			}
			if client.Err() != nil || server.Err() != nil {
				t.Fatal("stream result retired session")
			}
		})
	}
}

func TestOpeningConfirmationWithholdsVisitorPrefix(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, server := newAuthenticatedPair(t)
		opened := tunnelWorker(t, func() { _ = client.Close() }, func() error {
			stream, err := client.OpenInternalForwardingStream(tunnelContext(t), internalForwardingHeader(), []byte("proxy"), []byte("visitor"), ReturnEvents{})
			if stream != nil {
				_ = stream.Close()
			}
			return err
		})
		v, err := server.AcceptInternalForwardingStream(tunnelContext(t))
		if err != nil {
			t.Fatal(err)
		}
		defer v.Stream().Close()
		if got := v.(*IncomingPublicForwardingStream).TakeInitial(); string(got) != "proxy" {
			t.Fatalf("visitor sent before confirmation: %q", got)
		}
		synctest.Wait()
		select {
		case err := <-opened:
			t.Fatalf("opening skipped confirmation: %v", err)
		default:
		}
		if err := v.Accept(); err != nil {
			t.Fatal(err)
		}
		var prefix [7]byte
		if _, err := io.ReadFull(v.Stream(), prefix[:]); err != nil || string(prefix[:]) != "visitor" {
			t.Fatal("confirmation lost prefix", err)
		}
		if err := await(t, opened); err != nil {
			t.Fatal(err)
		}
	})
}

type cutOpeningTransport struct {
	muxsession.Session
	count   int
	failure error
}

func (s cutOpeningTransport) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	return &cutOpeningStream{Stream: stream, count: s.count, failure: s.failure}, nil
}

type cutOpeningStream struct {
	muxsession.Stream
	count   int
	failure error
}

func (s *cutOpeningStream) Write([]byte) (int, error) { return s.count, s.failure }

func TestOpeningErrorRetainsPartialCommitAndCause(t *testing.T) {
	h := internalForwardingHeader()
	h.ConfirmBeforeBytes = false
	proxy, initial := []byte("proxy"), []byte("visitor")
	var wire bytes.Buffer
	if _, err := tunnelv1.WriteForwardingOpening(&wire, h, proxy, initial); err != nil {
		t.Fatal(err)
	}
	boundary := wire.Len() - len(initial)
	for _, n := range []int{0, boundary - 1, boundary, boundary + 1, wire.Len()} {
		client, _ := newAuthenticatedPair(t)
		cause := errors.New("partial stream write")
		client.transport = cutOpeningTransport{Session: client.transport, count: n, failure: cause}
		stream, err := client.OpenInternalForwardingStream(tunnelContext(t), h, proxy, initial, ReturnEvents{})
		var opening *OpeningError
		if stream != nil || !errors.As(err, &opening) || !errors.Is(err, cause) || opening.VisitorBytes != int64(max(0, n-boundary)) || opening.Committed != (n > boundary) {
			t.Fatalf("cut %d lost retry boundary: %+v", n, err)
		}
		if client.Err() != nil {
			t.Fatal("partial write closed borrowed session")
		}
	}
}

func TestOpeningCancellationAfterPartialPrefixKeepsCommit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, server := newAuthenticatedPair(t)
		h := internalForwardingHeader()
		h.ConfirmBeforeBytes = false
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		opened := tunnelWorker(t, func() { _ = client.Close() }, func() error {
			stream, err := client.OpenInternalForwardingStream(ctx, h, []byte("proxy"), []byte("visitor"), ReturnEvents{})
			if stream != nil {
				_ = stream.Close()
			}
			return err
		})
		peer, err := server.transport.AcceptStream(tunnelContext(t))
		if err != nil {
			t.Fatal(err)
		}
		defer peer.Close()
		if _, err := tunnelv1.ReadInternalForwardingHeader(peer); err != nil {
			t.Fatal(err)
		}
		// length, PROXY metadata, and exactly one visitor byte have crossed.
		if _, err := io.ReadFull(peer, make([]byte, 4+len("proxy")+1)); err != nil {
			t.Fatal(err)
		}
		cancel()
		synctest.Wait()
		err = await(t, opened)
		var opening *OpeningError
		if !errors.As(err, &opening) || !errors.Is(err, context.Canceled) || !opening.Committed || opening.VisitorBytes != 1 {
			t.Fatalf("canceled prefix lost retry boundary: %v", err)
		}
		if client.Err() != nil || server.Err() != nil {
			t.Fatal("canceled opening closed session")
		}
	})
}

func TestOpeningMaximumHeaderAndInitialBlock(t *testing.T) {
	client, server := newAuthenticatedPair(t)
	h := maximumPublicHeader(strings.Repeat("\x01", 256))
	h.ConfirmBeforeBytes = false
	initial := bytes.Repeat([]byte{0xff}, tunnelv1.MaxInitialBytes)
	wantHeader, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	worker := tunnelWorker(t, func() { _ = server.Close() }, func() error {
		incoming, err := server.AcceptInternalForwardingStream(tunnelContext(t))
		if err != nil {
			return err
		}
		defer incoming.Stream().Close()
		request := incoming.(*IncomingPublicForwardingStream)
		gotHeader, err := json.Marshal(request.Header)
		if err != nil {
			return err
		}
		if !bytes.Equal(gotHeader, wantHeader) || !bytes.Equal(request.TakeInitial(), initial) {
			return errors.New("maximum opening changed header or bytes")
		}
		if err := request.Accept(); err != nil {
			return err
		}
		return request.Stream().CloseWrite()
	})
	stream, err := client.OpenInternalForwardingStream(tunnelContext(t), h, nil, initial, ReturnEvents{})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := io.Copy(io.Discard, stream); err != nil {
		t.Fatal(err)
	}
	if err := await(t, worker); err != nil {
		t.Fatal(err)
	}
}
