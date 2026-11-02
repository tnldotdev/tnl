package peer

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

// the recorder isolates scheduling from QUIC's intentionally lossy receive
// queue. it never blocks a send and retains only the bounded staged workload.
type recordingDatagrams struct{ sent chan []byte }

func (d recordingDatagrams) SupportsDatagrams() bool { return true }
func (d recordingDatagrams) SendDatagram(_ context.Context, frame []byte) error {
	d.sent <- frame
	return nil
}
func (d recordingDatagrams) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, context.Cause(ctx)
}

var _ muxsession.DatagramSession = recordingDatagrams{}

type stalledDatagrams struct {
	started chan struct{}
	once    sync.Once
}

func (*stalledDatagrams) SupportsDatagrams() bool { return true }
func (d *stalledDatagrams) SendDatagram(ctx context.Context, _ []byte) error {
	d.once.Do(func() { close(d.started) })
	<-ctx.Done()
	return context.Cause(ctx)
}
func (*stalledDatagrams) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, context.Cause(ctx)
}

var _ muxsession.DatagramSession = (*stalledDatagrams)(nil)

func TestPeerSharedDatagramsCloseJoinsStalledOuterSubmission(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	transport := &stalledDatagrams{started: make(chan struct{})}
	owner, err := NewSharedDatagrams(ctx, transport)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	binding, _ := sharedBinding(t, 1, RelayA)
	carrier, err := owner.Register(binding)
	if err != nil {
		t.Fatal(err)
	}
	if err := carrier.Send(ctx, signedFrame(t, binding)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-transport.started:
	case <-ctx.Done():
		t.Fatal("outer submission did not start")
	}
	done := make(chan error, 1)
	go func() { done <- owner.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("shared owner waited for outer session shutdown")
	}
	if err := ctx.Err(); err != nil {
		t.Fatal("borrower close canceled shared transport lifetime", err)
	}
	if _, err := carrier.Receive(ctx); !errors.Is(err, net.ErrClosed) {
		t.Fatal("stopped registration retained packet reader", err)
	}
}

func TestPeerSharedDatagramsRetirementInterruptsStalledSubmission(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "close", true: "new generation"}[replace], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			transport := &stalledDatagrams{started: make(chan struct{})}
			owner, err := NewSharedDatagrams(ctx, transport)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = owner.Close() })
			binding, _ := sharedBinding(t, 1, RelayA)
			carrier, err := owner.Register(binding)
			if err != nil {
				t.Fatal(err)
			}
			if err := carrier.Send(ctx, signedFrame(t, binding)); err != nil {
				t.Fatal(err)
			}
			select {
			case <-transport.started:
			case <-ctx.Done():
				t.Fatal("outer submission did not start")
			}
			retired := make(chan error, 1)
			go func() {
				if replace {
					binding.Delivery.Generation++
					_, err := owner.Register(binding)
					retired <- err
				} else {
					retired <- carrier.Close()
				}
			}()
			select {
			case err := <-retired:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("registration retirement waited for outer queue")
			}
			if _, err := carrier.Receive(ctx); !errors.Is(err, net.ErrClosed) {
				t.Fatal("retired registration retained packet reader", err)
			}
			other, _ := sharedBinding(t, 2, RelayA)
			if _, err := owner.Register(other); err != nil || owner.ctx.Err() != nil {
				t.Fatal("retirement canceled the shared owner", err, owner.ctx.Err())
			}
		})
	}
}

func TestPeerSharedDatagramsRoundRobinAndQueueBounds(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	recorder := recordingDatagrams{sent: make(chan []byte, sharedGlobalQueue)}
	// stage work through the real registration and Send paths before starting
	// the real writer. no scheduler timing can drain queues during this setup.
	owner := &SharedDatagrams{conn: recorder, ctx: ctx, cancel: cancel,
		peers: make(map[[16]byte]*sharedPeer), lastGeneration: make(map[[16]byte]uint64), wake: make(chan struct{}, 1)}
	t.Cleanup(func() { _ = owner.Close() })
	const senders = sharedGlobalQueue / sharedQueuePerPeer
	for index := range senders {
		binding, _ := sharedBinding(t, byte(index+1), RelayA)
		carrier, err := owner.Register(binding)
		if err != nil {
			t.Fatal(err)
		}
		defer carrier.Close()
		frame := signedFrame(t, binding)
		for range sharedQueuePerPeer + 1 {
			if err := carrier.Send(ctx, frame); err != nil {
				t.Fatal(err)
			}
		}
		if len(owner.order[index].out) != sharedQueuePerPeer || owner.order[index].drops != 1 {
			t.Fatal("per-peer queue did not bound and drop overflow")
		}
	}
	extra, _ := sharedBinding(t, byte(senders+1), RelayA)
	extraCarrier, err := owner.Register(extra)
	if err != nil {
		t.Fatal(err)
	}
	defer extraCarrier.Close()
	if err := extraCarrier.Send(ctx, signedFrame(t, extra)); err != nil {
		t.Fatal(err)
	}
	queued, peak, drops := owner.QueueStats()
	if queued != sharedGlobalQueue || peak != sharedGlobalQueue || drops != senders+1 || len(owner.order[senders].out) != 0 {
		t.Fatal("global queue did not bound and drop overflow", queued, peak, drops)
	}
	owner.wait.Go(owner.writeLoop)
	for packet := range sharedGlobalQueue {
		select {
		case frame := <-recorder.sent:
			delivery, err := tunnelv1.ParsePeerDeliveryHeader(frame[:tunnelv1.PeerDeliveryHeaderBytes])
			if err != nil || delivery.Pair[0] != byte(packet%senders+1) {
				t.Fatal("busy peer displaced a sibling's turn", packet, delivery, err)
			}
		case <-ctx.Done():
			t.Fatal("bounded writer did not drain", context.Cause(ctx))
		}
	}
	if queued, _, _ := owner.QueueStats(); queued != 0 {
		t.Fatal("writer did not release global capacity", queued)
	}
}
