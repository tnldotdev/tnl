package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"testing/synctest"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestServiceOpeningWithholdsVisitorBytesUntilAcceptance(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, server := newAuthenticatedPair(t)
		opened := tunnelWorker(t, func() { _ = client.Close() }, func() error {
			stream, err := client.OpenServiceForwardingStream(tunnelContext(t), serviceStreamHeader())
			if err != nil {
				return err
			}
			defer stream.Close()
			_, err = stream.Write([]byte("visitor"))
			return err
		})
		v, err := server.AcceptServiceForwardingStream(tunnelContext(t))
		if err != nil {
			t.Fatal(err)
		}
		defer v.Stream().Close()
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
			t.Fatal("confirmation lost visitor bytes", err)
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

func TestServiceOpeningMetadataFailureNeverClaimsVisitorCommit(t *testing.T) {
	var wire bytes.Buffer
	if _, err := tunnelv1.WriteServiceOpening(&wire, serviceStreamHeader()); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, wire.Len() - 1, wire.Len()} {
		client, _ := newAuthenticatedPair(t)
		cause := errors.New("partial stream write")
		client.transport = cutOpeningTransport{Session: client.transport, count: n, failure: cause}
		stream, err := client.OpenServiceForwardingStream(tunnelContext(t), serviceStreamHeader())
		var opening *OpeningError
		if stream != nil || !errors.As(err, &opening) || !errors.Is(err, cause) || opening.Step != "write_opening" || opening.VisitorBytes != 0 || opening.Committed {
			t.Fatalf("cut %d incorrectly crossed visitor retry boundary: %+v", n, err)
		}
		if client.Err() != nil {
			t.Fatal("partial metadata write closed shared session")
		}
	}
}

func TestServiceOpeningCancellationKeepsSessionUsable(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, server := newAuthenticatedPair(t)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		opened := tunnelWorker(t, func() { _ = client.Close() }, func() error {
			stream, err := client.OpenServiceForwardingStream(ctx, serviceStreamHeader())
			if stream != nil {
				_ = stream.Close()
			}
			return err
		})
		v, err := server.AcceptServiceForwardingStream(tunnelContext(t))
		if err != nil {
			t.Fatal(err)
		}
		defer v.Stream().Close()
		synctest.Wait()
		cancel()
		synctest.Wait()
		err = await(t, opened)
		var opening *OpeningError
		if !errors.As(err, &opening) || !errors.Is(err, context.Canceled) || opening.Step != "wait_for_ack" || opening.Committed || opening.VisitorBytes != 0 {
			t.Fatalf("canceled opening incorrectly crossed retry boundary: %v", err)
		}
		if client.Err() != nil || server.Err() != nil {
			t.Fatal("canceled opening closed shared session")
		}
	})
}

func TestServiceOpeningMaximumHeaderAndStreaming(t *testing.T) {
	client, server := newAuthenticatedPair(t)
	h := maximumServiceHeader("relay")
	h.ServiceID, h.ServiceRunID, h.RunNumber = publisherHello().ServiceConnection.ServiceID, publisherHello().ServiceConnection.ServiceRunID, publisherHello().ServiceConnection.RunNumber
	h.PublisherConnectionID, h.ConnectionAssignmentRevision, h.ConnectionSlot, h.RelayServiceID = publisherHello().ServiceConnection.PublisherConnectionID, publisherHello().ServiceConnection.ConnectionAssignmentRevision, publisherHello().ServiceConnection.ConnectionSlot, publisherHello().ServiceConnection.RelayServiceID
	initial := bytes.Repeat([]byte{0xff}, tunnelv1.MaxInitialBytes)
	worker := tunnelWorker(t, func() { _ = server.Close() }, func() error {
		incoming, err := server.AcceptServiceForwardingStream(tunnelContext(t))
		if err != nil {
			return err
		}
		defer incoming.Stream().Close()
		got, err := json.Marshal(incoming.Header)
		if err != nil {
			return err
		}
		want, err := json.Marshal(h)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, want) {
			return errors.New("maximum opening changed header")
		}
		if err := incoming.Accept(); err != nil {
			return err
		}
		received := make([]byte, len(initial))
		if _, err := io.ReadFull(incoming.Stream(), received); err != nil || !bytes.Equal(received, initial) {
			return errors.New("streaming changed visitor bytes")
		}
		return incoming.Stream().CloseWrite()
	})
	stream, err := client.OpenServiceForwardingStream(tunnelContext(t), h)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Write(initial); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, stream); err != nil {
		t.Fatal(err)
	}
	if err := await(t, worker); err != nil {
		t.Fatal(err)
	}
}
