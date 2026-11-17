package service

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

type pendingCapacityCloseGate struct {
	entered chan struct{}
	release chan struct{}
	result  chan error
	once    sync.Once
}

type pendingCapacityCloseTransport struct {
	muxsession.Session
	gate    *pendingCapacityCloseGate
	streams atomic.Int32
}

func (s *pendingCapacityCloseTransport) AcceptStream(ctx context.Context) (muxsession.Stream, error) {
	stream, err := s.Session.AcceptStream(ctx)
	if err != nil || s.streams.Add(1) == 1 {
		// the first stream is the authenticated publisher hello.
		return stream, err
	}
	return &pendingCapacityCloseStream{Stream: stream, gate: s.gate}, nil
}

type pendingCapacityCloseStream struct {
	muxsession.Stream
	gate *pendingCapacityCloseGate
}

func (s *pendingCapacityCloseStream) Close() error {
	s.gate.once.Do(func() { close(s.gate.entered) })
	<-s.gate.release
	err := s.Stream.Close()
	s.gate.result <- err
	return err
}

func TestServiceHTTPPendingShutdownJoinsCapacityBeforeClosingPublisher(t *testing.T) {
	gate := &pendingCapacityCloseGate{
		entered: make(chan struct{}), release: make(chan struct{}), result: make(chan error, 1),
	}
	release := sync.OnceFunc(func() { close(gate.release) })
	defer release()
	f := newPendingHTTPFixture(t, 1, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), func(outer muxsession.Session) muxsession.Session {
		return &pendingCapacityCloseTransport{Session: outer, gate: gate}
	})
	visitor := f.mustOpen(t, 0, pendingHTTPSource(0))
	pendingHTTPResponse(t, visitor.request(t, "/healthy"), http.StatusNoContent)
	claimedAwait(t, gate.entered)
	slot := f.current[0]
	cancelPublisher, cancelCapacity := slot.cancel, slot.cancelCapacity
	slot.cancelCapacity = func() { cancelCapacity(); release() }
	slot.cancel = func() {
		cancelPublisher()
		// if publisher cancellation comes first, its real session close reaches
		// the relay before the held capacity worker can physically close.
		claimedAwait(t, slot.relay.Done())
		if err := slot.relay.Close(); err != nil {
			t.Error("join relay session end before releasing capacity cleanup", err)
		}
		release()
	}
	slot.stop(t)
	if err := claimedAwait(t, gate.result); err != nil {
		t.Fatal("publisher teardown overtook entered capacity cleanup", err)
	}
	if f.calls.Load() != 1 || f.capacity.Load() != 1 {
		t.Fatal("shutdown changed the original request or capacity decision", f.calls.Load(), f.capacity.Load())
	}
}
