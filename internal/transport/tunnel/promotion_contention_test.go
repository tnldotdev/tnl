package tunnel

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
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

func TestPromotionCancellationWhileReturnWriterOwnsLock(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	defer local.Close()
	wire := &promotionWriteSignal{Stream: &memoryStream{Conn: local}, entered: make(chan struct{})}
	header := internalForwardingHeader().Admission()
	header.Kind, header.RelayID, header.RelayRunID, header.RelayLeaseRevision = tunnelv1.PublisherPromotion, "", "", 0
	reply := &replyStream{Stream: wire, accepted: true, promotion: header}
	written := make(chan error, 1)
	go func() { _, err := reply.Write([]byte("TLS bytes")); written <- err; close(written) }()
	t.Cleanup(func() { _ = local.Close(); await(t, written) })
	await(t, wire.entered)
	ctx, cancel := context.WithCancel(t.Context())
	promoted := make(chan error, 1)
	go func() { promoted <- reply.promote(ctx, reply.promotion); close(promoted) }()
	t.Cleanup(func() { cancel(); _ = local.Close(); await(t, promoted) })
	cancel()
	select {
	case err := <-promoted:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled promotion: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("promotion ignored cancellation behind a blocked return writer")
	}
}
