package tunnel

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
)

type promotionWriteSignal struct {
	muxsession.Stream
	entered chan struct{}
	once    sync.Once
}

func (s *promotionWriteSignal) Write(p []byte) (int, error) {
	s.once.Do(func() { close(s.entered) })
	return s.Stream.Write(p)
}

func TestEndCancellationWhileReturnWriterOwnsLock(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	defer local.Close()
	wire := &promotionWriteSignal{Stream: &memoryStream{Conn: local}, entered: make(chan struct{})}
	reply := &replyStream{Stream: wire, accepted: true}
	written := make(chan error, 1)
	go func() { _, err := reply.Write([]byte("TLS bytes")); written <- err; close(written) }()
	t.Cleanup(func() { _ = local.Close(); await(t, written) })
	await(t, wire.entered)
	ctx, cancel := context.WithCancel(t.Context())
	ended := make(chan error, 1)
	go func() { ended <- reply.end(ctx); close(ended) }()
	t.Cleanup(func() { cancel(); _ = local.Close(); await(t, ended) })
	cancel()
	select {
	case err := <-ended:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled end: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("end ignored cancellation behind a blocked return writer")
	}
}
