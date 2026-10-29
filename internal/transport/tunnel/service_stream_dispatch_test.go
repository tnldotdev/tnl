package tunnel

import (
	"bytes"
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func expiredForwardingFixture(t *testing.T) (*ServiceStreamDispatcher, *Session, *Session, tunnelv1.ServiceForwardingHeader) {
	t.Helper()
	header := maximumServiceHeader("relay-one", false)
	header.ExpiresAt = time.Now().UTC().Add(time.Minute)
	header.LeaseExpiresAt = header.ExpiresAt
	ref := ServiceForwardingRef(header)
	owner, sender := newHeaderBoundsPair(t, tunnelv1.Message{Type: tunnelv1.Hello, ProtocolVersion: tunnelv1.Version,
		Role: tunnelv1.Publisher, Credential: "test-credential", ServiceConnection: &ref})
	d, err := NewServiceStreamDispatcher(t.Context(), owner, blockedPeerIntroduction{started: make(chan struct{})})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	stream, err := sender.transport.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.Close() })
	wrote := make(chan error, 1)
	go func() { wrote <- tunnelv1.WriteServiceForwardingHeader(stream, header) }()
	queued := await(t, d.queue)
	if err := await(t, wrote); err != nil {
		t.Fatal(err)
	}
	// expire the actual queued opening without waiting for the production
	// ten-second timer. join its close callback before the consumer sees it.
	if queued.timer.Stop() {
		queued.timer.Reset(0)
	}
	await(t, queued.done)
	d.queue <- queued
	return d, owner, sender, header
}

func TestServiceDispatcherSkipsExpiredOpeningThroughClaimedConsumer(t *testing.T) {
	d, owner, sender, header := expiredForwardingFixture(t)
	stream, err := sender.transport.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	wrote := make(chan error, 1)
	go func() { _, err := tunnelv1.WriteServiceOpening(stream, header, []byte("visitor")); wrote <- err }()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	incoming, err := owner.AcceptDispatchedServiceForwardingStream(ctx, d)
	if err != nil {
		t.Fatalf("expired opening hid a live forwarding stream: %v", err)
	}
	defer incoming.Stream().Close()
	if !reflect.DeepEqual(incoming.Header, header) || !bytes.Equal(incoming.TakeInitial(), []byte("visitor")) {
		t.Fatal("claimed forwarding header or visitor bytes changed")
	}
	if err := await(t, wrote); err != nil {
		t.Fatal(err)
	}
	if owner.transport.Err() != nil || sender.transport.Err() != nil {
		t.Fatal("expired opening closed the borrowed session")
	}
}

func TestServiceDispatcherWaitsAfterExpiredOpeningUntilCallerEnds(t *testing.T) {
	d, _, sender, _ := expiredForwardingFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	if _, err := d.AcceptForwardingStream(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("expired opening was reported as dispatcher shutdown", err)
	}
	if sender.transport.Err() != nil {
		t.Fatal("caller cancellation closed the borrowed session")
	}
}

type blockedPeerIntroduction struct{ started chan struct{} }

func (p blockedPeerIntroduction) AcceptIntroduction(ctx context.Context, stream muxsession.Stream) {
	defer stream.Close()
	close(p.started)
	var b [1]byte
	_, _ = stream.Read(b[:])
}

func TestServiceDispatcherCloseJoinsPartialHeaders(t *testing.T) {
	client, server := newMemoryPair(t)
	ref := tunnelv1.ServicePublisherConnectionRef{}
	owner := &Session{transport: server, role: tunnelv1.Publisher, serviceConnection: &ref}
	peer := blockedPeerIntroduction{started: make(chan struct{})}
	d, err := NewServiceStreamDispatcher(t.Context(), owner, peer)
	if err != nil {
		t.Fatal(err)
	}
	peerStream, err := client.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer peerStream.Close()
	go func() { _, _ = peerStream.Write([]byte{tunnelv1.Version}) }()
	await(t, peer.started)
	partial, err := client.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer partial.Close()
	go func() { _, _ = partial.Write([]byte{0, 0, 0, 5}) }()
	result := make(chan error, 1)
	go func() { result <- d.Close() }()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("partial header workers survived dispatcher shutdown")
	}
	if len(d.reads) != 0 || len(d.peers) != 0 || len(d.forwards) != 0 {
		t.Fatal("dispatcher returned with live readers")
	}
	if client.Err() != nil || server.Err() != nil {
		t.Fatal("dispatcher closed borrowed session")
	}
	if _, err := d.AcceptForwardingStream(t.Context()); !errors.Is(err, net.ErrClosed) {
		t.Fatal("closed dispatcher accepted forwarding", err)
	}
}

func TestServiceDispatcherPreemptsUnclassifiedHeaders(t *testing.T) {
	client, server := newMemoryPair(t)
	ref := tunnelv1.ServicePublisherConnectionRef{}
	d, err := NewServiceStreamDispatcher(t.Context(), &Session{transport: server, role: tunnelv1.Publisher, serviceConnection: &ref}, blockedPeerIntroduction{started: make(chan struct{})})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	for range serviceDispatchReaders {
		stream, err := client.OpenStream(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer stream.Close()
	}
	until := time.Now().Add(time.Second)
	for len(d.reads) != serviceDispatchReaders && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if len(d.reads) != serviceDispatchReaders {
		t.Fatal("first-byte readers did not fill")
	}
	forward, err := client.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer forward.Close()
	wrote := make(chan error, 1)
	go func() { _, err := forward.Write([]byte{0, 0, 0, 5}); wrote <- err }()
	if err := await(t, wrote); err != nil {
		t.Fatal(err)
	}
	until = time.Now().Add(time.Second)
	for len(d.forwards) == 0 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if len(d.forwards) == 0 {
		t.Fatal("stalled first-byte readers starved forwarding")
	}
}
