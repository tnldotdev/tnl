package tunnel

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

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
