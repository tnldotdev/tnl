package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const (
	serviceDispatchReaders  = 8
	serviceDispatchPeers    = 8
	serviceDispatchForwards = 8
	serviceDispatchQueue    = 32
	serviceDispatchTimeout  = time.Second
)

// PeerStreamIntroduction consumes a classified peer stream. the implementation
// must close invalid introductions and retain only authenticated ones.
type PeerStreamIntroduction interface {
	AcceptIntroduction(context.Context, muxsession.Stream)
}

// ServiceStreamDispatcher is the sole AcceptStream reader on an already
// authenticated TLS/yamux session. it borrows the session and never grants
// permission to forward a visitor or to register a peer pair.
type ServiceStreamDispatcher struct {
	ctx      context.Context
	cancel   context.CancelFunc
	owner    *Session
	outer    muxsession.Session
	peer     PeerStreamIntroduction
	queue    chan *queuedForward
	reads    chan struct{}
	peers    chan struct{}
	forwards chan struct{}
	mu       sync.Mutex
	active   map[muxsession.Stream]struct{}
	reading  []muxsession.Stream
	wait     sync.WaitGroup
	once     sync.Once
}

type queuedForward struct {
	stream muxsession.Stream
	timer  *time.Timer
	done   chan struct{}
}

func (q *queuedForward) stop() bool {
	if q.timer.Stop() {
		return true
	}
	<-q.done
	return false
}

// NewServiceStreamDispatcher starts accepting after the service publisher's v1
// control handshake. while it runs, no other caller may accept from that outer
// session. close and join it before closing the peer owner and tunnel session.
func NewServiceStreamDispatcher(parent context.Context, owner *Session, peer PeerStreamIntroduction) (*ServiceStreamDispatcher, error) {
	if parent == nil || owner == nil || owner.transport == nil || owner.role != tunnelv1.Publisher || owner.serviceConnection == nil || peer == nil {
		return nil, errors.New("service stream dispatcher needs a claimed service publisher session and peer acceptor")
	}
	ctx, cancel := context.WithCancel(parent)
	d := &ServiceStreamDispatcher{ctx: ctx, cancel: cancel, owner: owner, outer: owner.transport, peer: peer,
		queue: make(chan *queuedForward, serviceDispatchQueue), reads: make(chan struct{}, serviceDispatchReaders),
		peers: make(chan struct{}, serviceDispatchPeers), forwards: make(chan struct{}, serviceDispatchForwards),
		active: make(map[muxsession.Stream]struct{})}
	d.wait.Go(d.acceptLoop)
	return d, nil
}

func (d *ServiceStreamDispatcher) acceptLoop() {
	for d.ctx.Err() == nil {
		stream, err := d.outer.AcceptStream(d.ctx)
		if err != nil {
			d.cancel()
			return
		}
		d.mu.Lock()
		if d.ctx.Err() != nil {
			d.mu.Unlock()
			_ = stream.Close()
			return
		}
		d.active[stream] = struct{}{}
		d.mu.Unlock()
		select {
		case d.reads <- struct{}{}:
		default:
			// when all first-byte readers are stalled, interrupt the oldest
			// unclassified stream so a new forwarding stream gets a reader.
			d.mu.Lock()
			var oldest muxsession.Stream
			if len(d.reading) != 0 {
				oldest = d.reading[0]
			}
			d.mu.Unlock()
			if oldest != nil {
				_ = oldest.SetReadDeadline(time.Now())
			}
			select {
			case d.reads <- struct{}{}:
			case <-d.ctx.Done():
				d.release(stream, true)
				return
			}
		}
		d.mu.Lock()
		d.reading = append(d.reading, stream)
		d.mu.Unlock()
		d.wait.Go(func() {
			defer func() {
				d.mu.Lock()
				for i, reader := range d.reading {
					if reader == stream {
						d.reading = append(d.reading[:i], d.reading[i+1:]...)
						break
					}
				}
				d.mu.Unlock()
				<-d.reads
			}()
			d.classify(stream)
		})
	}
}

func (d *ServiceStreamDispatcher) release(stream muxsession.Stream, closeStream bool) {
	d.mu.Lock()
	delete(d.active, stream)
	d.mu.Unlock()
	if closeStream {
		_ = stream.Close()
	}
}

func (d *ServiceStreamDispatcher) classify(stream muxsession.Stream) {
	keep := false
	defer func() { d.release(stream, !keep) }()
	if err := stream.SetReadDeadline(time.Now().Add(serviceDispatchTimeout)); err != nil {
		return
	}
	var prefix [4]byte
	if _, err := io.ReadFull(stream, prefix[:1]); err != nil {
		return
	}
	if prefix[0] == tunnelv1.Version {
		select {
		case d.peers <- struct{}{}:
			// a peer's full header and tagged first frame are checked by the
			// registered pair; slow peers cannot occupy classifier readers.
			d.wait.Go(func() {
				defer func() { <-d.peers }()
				d.peer.AcceptIntroduction(d.ctx, &prefixedStream{Stream: stream, prefix: bytes.NewReader(prefix[:1])})
				d.release(stream, false)
			})
			keep = true
		default:
		}
		return
	}
	if prefix[0] != 0 {
		return
	}
	if _, err := io.ReadFull(stream, prefix[1:]); err != nil {
		return
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n == 0 || n > tunnelv1.MaxServiceHeaderBytes {
		return
	}
	select {
	case d.forwards <- struct{}{}:
		d.wait.Go(func() {
			defer func() { <-d.forwards }()
			d.readForwardingHeader(stream, prefix, n)
		})
		keep = true
	default:
	}
}

func (d *ServiceStreamDispatcher) readForwardingHeader(stream muxsession.Stream, prefix [4]byte, n uint32) {
	keep := false
	defer func() { d.release(stream, !keep) }()
	// only the bounded frame is buffered. the forwarding owner still checks
	// the claimed assignment and reads the original opening from byte zero.
	frame := make([]byte, 4+int(n))
	copy(frame, prefix[:])
	if _, err := io.ReadFull(stream, frame[4:]); err != nil {
		return
	}
	if _, err := tunnelv1.ReadServiceForwardingHeader(bytes.NewReader(frame)); err != nil {
		return
	}
	if err := stream.SetReadDeadline(time.Time{}); err != nil {
		return
	}
	forward := &prefixedStream{Stream: stream, prefix: bytes.NewReader(frame)}
	q := &queuedForward{stream: forward, done: make(chan struct{})}
	q.timer = time.AfterFunc(handshakeTimeout, func() { _ = stream.Close(); close(q.done) })
	select {
	case d.queue <- q:
		keep = true
	default:
		q.stop()
	}
}

type prefixedStream struct {
	muxsession.Stream
	prefix *bytes.Reader
}

func (s *prefixedStream) Read(b []byte) (int, error) {
	if s.prefix.Len() > 0 {
		return s.prefix.Read(b)
	}
	return s.Stream.Read(b)
}

// AcceptForwardingStream returns the untouched v1 forwarding frame for the
// authenticated tunnel session's existing service-forwarding checks.
func (d *ServiceStreamDispatcher) AcceptForwardingStream(ctx context.Context) (muxsession.Stream, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-d.ctx.Done():
			return nil, net.ErrClosed
		case q := <-d.queue:
			if !q.stop() {
				// an unclaimed opening expired, not the dispatcher or its
				// borrowed session. keep waiting for a live forwarding stream.
				continue
			}
			if d.ctx.Err() != nil || ctx.Err() != nil {
				_ = q.stream.Close()
				return nil, net.ErrClosed
			}
			return q.stream, nil
		}
	}
}

// Close interrupts and joins classification and peer introduction workers.
// the caller still owns both the outer session and the peer owner.
func (d *ServiceStreamDispatcher) Close() error {
	d.once.Do(func() {
		d.cancel()
		d.mu.Lock()
		for stream := range d.active {
			_ = stream.SetReadDeadline(time.Now())
		}
		d.mu.Unlock()
		d.wait.Wait()
		for {
			select {
			case q := <-d.queue:
				q.stop()
				_ = q.stream.Close()
			default:
				return
			}
		}
	})
	return nil
}
