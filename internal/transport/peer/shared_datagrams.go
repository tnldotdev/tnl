package peer

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"net"
	"sync"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const (
	sharedMaxPeers     = 64
	sharedQueuePerPeer = 16
	sharedGlobalQueue  = 256
	// keep bounded tombstones so an old generation cannot be reopened on this session.
	sharedMaxAdmissions = 4096
)

// PairBinding is supplied by the role owner after authenticating an exact pair,
// delivery generation, direction, and path. the identifier alone is never a service grant.
type PairBinding struct {
	Delivery tunnelv1.PeerDelivery
	Key      [32]byte
	Role     uint8
	Path     uint8
}

func (b PairBinding) valid() bool {
	return b.Delivery.Valid() && b.Key != [32]byte{} && b.Role <= 1 && b.Path <= RelayB
}

func (b PairBinding) authentic(frame []byte, sender uint8) bool {
	p, err := tunnelv1.ParsePeerPacket(frame)
	if err != nil || p.Sender != sender || p.Path != b.Path {
		return false
	}
	unsigned, err := p.AuthenticatedBytes()
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, b.Key[:])
	_, _ = mac.Write([]byte(connectorPacketDomain))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(unsigned)
	return hmac.Equal(p.MAC[:], mac.Sum(nil))
}

type sharedPeer struct {
	binding PairBinding
	ctx     context.Context
	cancel  context.CancelFunc
	in      chan []byte
	out     [][]byte
	done    chan struct{}
	drops   uint64
	replay  replayWindow
}

// replayWindow accepts two fragments of one sequence once, in any order,
// while bounding out-of-order delivery independently for each registration.
type replayWindow struct {
	highest   uint64
	sequence  [64]uint64
	fragments [64]uint8
}

func (w *replayWindow) accept(frame []byte) bool {
	p, err := tunnelv1.ParsePeerPacket(frame)
	if err != nil || (p.Sequence < w.highest && w.highest-p.Sequence >= uint64(len(w.sequence))) {
		return false
	}
	w.highest = max(w.highest, p.Sequence)
	slot := p.Sequence % uint64(len(w.sequence))
	if w.sequence[slot] != p.Sequence {
		w.sequence[slot], w.fragments[slot] = p.Sequence, 0
	}
	bit := uint8(1 << p.Fragment)
	if w.fragments[slot]&bit != 0 {
		return false
	}
	w.fragments[slot] |= bit
	return true
}

// SharedDatagrams borrows an authenticated outer QUIC connection. it never
// closes the connection. only this owner reads its datagrams; other protocols
// cannot concurrently consume them. callers join Close before retiring it.
type SharedDatagrams struct {
	conn           muxsession.DatagramSession
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.Mutex
	peers          map[[16]byte]*sharedPeer
	lastGeneration map[[16]byte]uint64
	order          []*sharedPeer
	next           int
	queued         int
	peak           int
	drops          uint64
	wake           chan struct{}
	closed         bool
	wait           sync.WaitGroup
	once           sync.Once
}

func NewSharedDatagrams(parent context.Context, conn muxsession.DatagramSession) (*SharedDatagrams, error) {
	if conn == nil || !conn.SupportsDatagrams() {
		return nil, ErrConfiguration
	}
	ctx, cancel := context.WithCancel(parent)
	s := &SharedDatagrams{conn: conn, ctx: ctx, cancel: cancel,
		peers: make(map[[16]byte]*sharedPeer), lastGeneration: make(map[[16]byte]uint64), wake: make(chan struct{}, 1)}
	s.wait.Go(s.readLoop)
	s.wait.Go(s.writeLoop)
	s.wait.Go(func() {
		<-ctx.Done()
		s.mu.Lock()
		s.closed = true
		for _, p := range s.order {
			close(p.done)
		}
		s.peers = nil
		s.order = nil
		s.mu.Unlock()
	})
	return s, nil
}

// Register transfers one live carrier to the endpoint. a pair may be replaced
// only with a strictly newer generation; tombstones prevent stale reuse. a full
// owner must be replaced with a fresh outer session, not grow without bound.
func (s *SharedDatagrams) Register(b PairBinding) (Carrier, error) {
	if !b.valid() {
		return nil, ErrConfiguration
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	id := b.Delivery.Pair
	if (len(s.order) >= sharedMaxPeers && s.peers[id] == nil) || b.Delivery.Generation <= s.lastGeneration[id] ||
		(s.lastGeneration[id] == 0 && len(s.lastGeneration) >= sharedMaxAdmissions) {
		return nil, ErrConfiguration
	}
	if old := s.peers[id]; old != nil {
		s.removeLocked(old)
	}
	ctx, cancel := context.WithCancel(s.ctx)
	p := &sharedPeer{binding: b, ctx: ctx, cancel: cancel, in: make(chan []byte, sharedQueuePerPeer), done: make(chan struct{})}
	s.peers[id] = p
	s.lastGeneration[id] = b.Delivery.Generation
	s.order = append(s.order, p)
	return &SharedDatagramCarrier{owner: s, peer: p}, nil
}

func (s *SharedDatagrams) removeLocked(p *sharedPeer) {
	if s.peers[p.binding.Delivery.Pair] != p {
		return
	}
	delete(s.peers, p.binding.Delivery.Pair)
	p.cancel()
	close(p.done)
	s.queued -= len(p.out)
	p.out = nil
	for i, candidate := range s.order {
		if candidate == p {
			s.order = append(s.order[:i], s.order[i+1:]...)
			if i < s.next {
				s.next--
			}
			if s.next >= len(s.order) {
				s.next = 0
			}
			break
		}
	}
}

func (s *SharedDatagrams) readLoop() {
	for {
		data, err := s.conn.ReceiveDatagram(s.ctx)
		if err != nil {
			s.cancel()
			return
		}
		if len(data) < tunnelv1.PeerDeliveryHeaderBytes || len(data) > tunnelv1.MaxPeerDeliveryBytes {
			continue
		}
		d, err := tunnelv1.ParsePeerDeliveryHeader(data[:tunnelv1.PeerDeliveryHeaderBytes])
		if err != nil {
			continue
		}
		s.mu.Lock()
		p := s.peers[d.Pair]
		if p != nil && p.binding.Delivery == d {
			_, frame, err := tunnelv1.OpenPeerDelivery(data, tunnelv1.PeerDeliveryDatagram, p.binding.Key)
			if err == nil && p.binding.authentic(frame, 1-p.binding.Role) && p.replay.accept(frame) {
				select {
				case p.in <- frame:
				default:
					p.drops++
					s.drops++
				}
			}
		}
		s.mu.Unlock()
	}
}

func (s *SharedDatagrams) writeLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.wake:
		}
		for {
			s.mu.Lock()
			if s.ctx.Err() != nil {
				s.mu.Unlock()
				return
			}
			var p *sharedPeer
			for range len(s.order) {
				candidate := s.order[s.next]
				s.next = (s.next + 1) % len(s.order)
				if len(candidate.out) != 0 {
					p = candidate
					break
				}
			}
			if p == nil {
				s.mu.Unlock()
				break
			}
			frame := p.out[0]
			p.out[0] = nil
			p.out = p.out[1:]
			s.queued--
			s.mu.Unlock()
			// never hold registration state across outer backpressure. retiring
			// this peer cancels its submission without retiring sibling peers or
			// the borrowed session. one submitted packet may already be in flight;
			// the receiver still checks its delivery generation and replay fence.
			err := s.conn.SendDatagram(p.ctx, frame)
			if err != nil {
				if p.ctx.Err() != nil {
					continue
				}
				// an oversized datagram is dropped for inner QUIC to recover;
				// connection errors terminate this owner.
				var tooLarge *quic.DatagramTooLargeError
				if !errors.As(err, &tooLarge) {
					s.cancel()
					return
				}
			}
		}
	}
}

// QueueStats includes both ingress and egress drops; queued counts egress only.
func (s *SharedDatagrams) QueueStats() (queued, peak int, drops uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.queued, s.peak, s.drops
}

func (s *SharedDatagrams) Close() error {
	s.once.Do(func() { s.cancel(); s.wait.Wait() })
	return nil
}

// SharedDatagramCarrier owns only this pair's registration, not the connection.
type SharedDatagramCarrier struct {
	owner *SharedDatagrams
	peer  *sharedPeer
	once  sync.Once
}

func (c *SharedDatagramCarrier) Drops() uint64 {
	c.owner.mu.Lock()
	defer c.owner.mu.Unlock()
	return c.peer.drops
}

func (c *SharedDatagramCarrier) Send(ctx context.Context, frame []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !c.peer.binding.authentic(frame, c.peer.binding.Role) {
		return tunnelv1.ErrPeerPacket
	}
	b, err := c.peer.binding.Delivery.Seal(tunnelv1.PeerDeliveryDatagram, c.peer.binding.Key, frame)
	if err != nil {
		return err
	}
	s := c.owner
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx.Err() != nil || s.peers[c.peer.binding.Delivery.Pair] != c.peer {
		return net.ErrClosed
	}
	if len(c.peer.out) == sharedQueuePerPeer || s.queued == sharedGlobalQueue {
		c.peer.drops++
		s.drops++
		return nil
	}
	c.peer.out = append(c.peer.out, b)
	s.queued++
	s.peak = max(s.peak, s.queued)
	select {
	case s.wake <- struct{}{}:
	default:
	}
	return nil
}

func (c *SharedDatagramCarrier) Receive(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.peer.done:
		return nil, net.ErrClosed
	case b := <-c.peer.in:
		// if close won the race, a buffered frame must not escape.
		select {
		case <-c.peer.done:
			return nil, net.ErrClosed
		default:
		}
		return b, nil
	}
}

func (c *SharedDatagramCarrier) Close() error {
	c.once.Do(func() {
		c.owner.mu.Lock()
		c.owner.removeLocked(c.peer)
		c.owner.mu.Unlock()
	})
	return nil
}
