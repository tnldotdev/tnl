package tunnel

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

type permissionDeadlineStream struct {
	muxsession.Stream
	deadlines chan time.Time
	writes    chan struct{}
}

func (s *permissionDeadlineStream) SetWriteDeadline(until time.Time) error {
	s.deadlines <- until
	return s.Stream.SetWriteDeadline(until)
}

func (s *permissionDeadlineStream) Write(data []byte) (int, error) {
	s.writes <- struct{}{}
	return s.Stream.Write(data)
}

type permissionDeadlineSession struct {
	muxsession.Session
	stream *permissionDeadlineStream
}

type permissionRejectedDeadline struct {
	muxsession.Stream
	err error
}

func (s *permissionRejectedDeadline) SetWriteDeadline(until time.Time) error {
	if s.err != nil {
		return s.err
	}
	return s.Stream.SetWriteDeadline(until)
}

func TestConnectorPermissionDeadlineFailureFencesQueuedSibling(t *testing.T) {
	client, server := newMemoryPair(t)
	writer, _ := permissionControlPair(t, client, server)
	failure := errors.New("cannot set shared stream deadline")
	stream := &permissionRejectedDeadline{Stream: writer.stream, err: failure}
	var gate ConnectorPermissionGate
	writeGate := make(chan struct{}, 1)
	wrote := false
	write := func(io.Writer) error { wrote = true; return nil }
	if shared, err := gate.write(tunnelContext(t), stream, writeGate, write); !shared || !errors.Is(err, failure) {
		t.Fatal("shared stream setup failure became a visitor-local failure", err)
	}
	stream.err = nil
	if shared, err := gate.write(tunnelContext(t), stream, writeGate, write); !shared || !errors.Is(err, failure) || wrote {
		t.Fatal("a sibling entered framing after the shared stream failed", err)
	}
}

func (s *permissionDeadlineSession) OpenStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	s.stream = &permissionDeadlineStream{Stream: stream, deadlines: make(chan time.Time, 8), writes: make(chan struct{}, 8)}
	return s.stream, nil
}

func permissionDeadlinePair(t *testing.T) (*ConnectorPermissionWriter, *permissionDeadlineStream) {
	t.Helper()
	client, server := newMemoryPair(t)
	tracked := &permissionDeadlineSession{Session: client}
	writer, _ := permissionControlPair(t, tracked, server)
	for len(tracked.stream.writes) > 0 {
		<-tracked.stream.writes // the completed control handshake.
	}
	return writer, tracked.stream
}

func TestConnectorPermissionRenewalRejectsInvalidDeadlineBeforeGatesOrIO(t *testing.T) {
	for _, name := range []string{"missing", "zero", "expired", "canceled"} {
		t.Run(name, func(t *testing.T) {
			writer, tracked := permissionDeadlinePair(t)
			ctx := t.Context()
			var cancel context.CancelFunc
			want := context.DeadlineExceeded
			switch name {
			case "zero":
				ctx, cancel = context.WithDeadline(ctx, time.Time{})
			case "expired":
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
			case "canceled":
				ctx, cancel = context.WithTimeout(ctx, time.Minute)
				cancel()
				want = context.Canceled
			}
			if cancel != nil {
				defer cancel()
			}
			writer.gate <- struct{}{}
			defer func() { <-writer.gate }()
			done := tunnelWorker(t, writer.Close, func() error { return writer.Renew(ctx, connectorPermissionFixture()) })
			select {
			case err := <-done:
				if !errors.Is(err, want) || len(tracked.deadlines) != 0 || len(tracked.writes) != 0 {
					t.Fatal("invalid renewal changed the deadline or wrote control bytes", err)
				}
			case <-time.After(time.Second):
				t.Fatal("invalid renewal waited for the write gate")
			}
		})
	}
}

func TestConnectorPermissionRenewalBlockedWriteKeepsDeadlineAndRetiresControl(t *testing.T) {
	writer, tracked := permissionDeadlinePair(t)
	until := time.Now().Add(100 * time.Millisecond)
	ctx, cancel := context.WithDeadline(t.Context(), until)
	defer cancel()
	done := tunnelWorker(t, writer.Close, func() error { return writer.Renew(ctx, connectorPermissionFixture()) })
	if at := await(t, tracked.deadlines); !at.Equal(until) {
		t.Fatal("renewal reset its original write deadline")
	}
	await(t, tracked.writes)
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal("blocked renewal lost its deadline cause", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked renewal write escaped its deadline")
	}
	await(t, writer.Done())
	if err := writer.Renew(tunnelContext(t), connectorPermissionFixture()); err == nil || len(tracked.writes) != 0 {
		t.Fatal("failed renewal allowed ambiguous control framing to resume", err)
	}
	if len(writer.gate) != 0 || len(writer.pending) != 0 {
		t.Fatal("failed renewal retained its write gate or pending acknowledgement")
	}
}

func TestConnectorPermissionCloseInterruptsBlockedRenewal(t *testing.T) {
	writer, tracked := permissionDeadlinePair(t)
	done := tunnelWorker(t, writer.Close, func() error { return writer.Renew(tunnelContext(t), connectorPermissionFixture()) })
	await(t, tracked.writes)
	closed := tunnelWorker(t, func() { _ = tracked.Stream.Reset(0) }, func() struct{} { writer.Close(); return struct{}{} })
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("control close did not join the blocked renewal")
	}
	if err := await(t, done); !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, context.Canceled) {
		t.Fatal("control close lost its blocked renewal cause", err)
	}
	if len(writer.gate) != 0 || len(writer.pending) != 0 {
		t.Fatal("closed renewal retained its write gate or pending acknowledgement")
	}
}
