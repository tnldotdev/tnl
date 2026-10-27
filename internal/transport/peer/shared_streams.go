package peer

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const (
	streamIntroductionTimeout = time.Second
	streamIntroductionWorkers = 8
)

// SharedStreams borrows exclusive acceptance of peer streams on one outer
// TLS/yamux session. it does not close the session during normal pair teardown;
// muxsession can still abort a session if stream cleanup itself stalls. the
// role owner must not also call AcceptStream on that session; other stream
// protocols need their own dispatcher above this owner.
type SharedStreams struct {
	session        muxsession.Session
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.Mutex
	pairs          map[[16]byte]*StreamPair
	lastGeneration map[[16]byte]uint64
	closed         bool
	wait           sync.WaitGroup
	introductions  sync.WaitGroup
	introSlots     chan struct{}
	opens          sync.WaitGroup
	once           sync.Once
}

type StreamPair struct {
	owner   *SharedStreams
	binding PairBinding
	pending chan *SharedStreamCarrier
	active  *SharedStreamCarrier
	done    chan struct{}
	ctx     context.Context
	cancel  context.CancelFunc
	opens   sync.WaitGroup
	replay  replayWindow
}

// NewSharedStreams takes ownership of stream acceptance, not of the session.
func NewSharedStreams(parent context.Context, session muxsession.Session) (*SharedStreams, error) {
	if session == nil {
		return nil, ErrConfiguration
	}
	ctx, cancel := context.WithCancel(parent)
	s := &SharedStreams{session: session, ctx: ctx, cancel: cancel,
		pairs: make(map[[16]byte]*StreamPair), lastGeneration: make(map[[16]byte]uint64),
		introSlots: make(chan struct{}, streamIntroductionWorkers)}
	s.wait.Go(s.acceptLoop)
	s.wait.Go(func() {
		<-ctx.Done()
		s.mu.Lock()
		s.closed = true
		var carriers []*StreamCarrier
		for _, p := range s.pairs {
			if carrier := s.removeLocked(p); carrier != nil {
				carriers = append(carriers, carrier)
			}
		}
		s.mu.Unlock()
		for _, carrier := range carriers {
			_ = carrier.Close()
		}
	})
	return s, nil
}

func (s *SharedStreams) Register(b PairBinding) (*StreamPair, error) {
	if !b.valid() {
		return nil, ErrConfiguration
	}
	s.mu.Lock()
	if s.closed || s.ctx.Err() != nil {
		s.mu.Unlock()
		return nil, net.ErrClosed
	}
	id := b.Delivery.Pair
	if (len(s.pairs) >= sharedMaxPeers && s.pairs[id] == nil) || b.Delivery.Generation <= s.lastGeneration[id] ||
		(s.lastGeneration[id] == 0 && len(s.lastGeneration) >= sharedMaxAdmissions) {
		s.mu.Unlock()
		return nil, ErrConfiguration
	}
	var oldCarrier *StreamCarrier
	if old := s.pairs[id]; old != nil {
		oldCarrier = s.removeLocked(old)
	}
	ctx, cancel := context.WithCancel(s.ctx)
	p := &StreamPair{owner: s, binding: b, pending: make(chan *SharedStreamCarrier, 1), done: make(chan struct{}), ctx: ctx, cancel: cancel}
	s.pairs[id] = p
	s.lastGeneration[id] = b.Delivery.Generation
	s.mu.Unlock()
	if oldCarrier != nil {
		_ = oldCarrier.Close()
	}
	return p, nil
}

func (s *SharedStreams) removeLocked(p *StreamPair) *StreamCarrier {
	if s.pairs[p.binding.Delivery.Pair] != p {
		return nil
	}
	delete(s.pairs, p.binding.Delivery.Pair)
	p.cancel()
	close(p.done)
	if p.active != nil && p.active.StreamCarrier != nil {
		return p.active.StreamCarrier
	}
	return nil
}

func (s *SharedStreams) acceptLoop() {
	for {
		select {
		case <-s.ctx.Done():
			return
		case s.introSlots <- struct{}{}:
		}
		stream, err := s.session.AcceptStream(s.ctx)
		if err != nil {
			<-s.introSlots
			s.cancel()
			return
		}
		s.introductions.Go(func() {
			defer func() { <-s.introSlots }()
			s.acceptIntroduction(stream)
		})
	}
}

func (s *SharedStreams) acceptIntroduction(stream muxsession.Stream) {
	// a blocked introduction holds only one of a fixed number of reader slots.
	var closeOnce sync.Once
	closeStream := func() { closeOnce.Do(func() { _ = stream.Close() }) }
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(s.ctx, func() { closeStream(); close(callbackDone) })
	keep := false
	defer func() {
		if !stop() {
			<-callbackDone
		}
		if !keep {
			closeStream()
		}
	}()
	if err := stream.SetReadDeadline(time.Now().Add(streamIntroductionTimeout)); err != nil {
		return
	}
	var header [tunnelv1.PeerDeliveryHeaderBytes]byte
	_, err := io.ReadFull(stream, header[:])
	if err != nil {
		return
	}
	d, err := tunnelv1.ParsePeerDeliveryHeader(header[:])
	if err != nil {
		return
	}
	s.mu.Lock()
	known := s.pairs[d.Pair]
	allowed := s.ctx.Err() == nil && known != nil && known.binding.Delivery == d && known.active == nil
	s.mu.Unlock()
	if !allowed {
		return
	}
	sealed, frame, err := tunnelv1.ReadPeerDeliveryFrame(stream, tunnelv1.PeerDeliveryStream, known.binding.Key)
	if err != nil || sealed != d {
		return
	}
	s.mu.Lock()
	p := s.pairs[d.Pair]
	if s.ctx.Err() != nil || p == nil || p.binding.Delivery != d || p.active != nil || len(p.pending) != 0 || !p.binding.authentic(frame, 1-p.binding.Role) {
		s.mu.Unlock()
		return
	}
	if err := stream.SetReadDeadline(time.Time{}); err != nil {
		s.mu.Unlock()
		return
	}
	if !p.replay.accept(frame) {
		s.mu.Unlock()
		return
	}
	c := &SharedStreamCarrier{StreamCarrier: &StreamCarrier{Conn: stream}, pair: p, first: frame}
	p.pending <- c // the admission slot was checked under the same lock.
	p.active = c
	keep = true
	s.mu.Unlock()
}

// Open writes the generation header before any framed peer packet. the receiver
// accepts the stream only after the first correctly MACed packet arrives.
func (p *StreamPair) Open(ctx context.Context) (*SharedStreamCarrier, error) {
	s := p.owner
	s.mu.Lock()
	if s.ctx.Err() != nil || s.pairs[p.binding.Delivery.Pair] != p || p.active != nil {
		s.mu.Unlock()
		return nil, net.ErrClosed
	}
	// reserve the only active stream while opening outside the lock.
	p.active = &SharedStreamCarrier{pair: p}
	reserved := p.active
	p.opens.Add(1)
	s.opens.Add(1)
	s.mu.Unlock()
	defer p.opens.Done()
	defer s.opens.Done()
	openCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(p.ctx, cancel)
	defer func() { stop(); cancel() }()
	stream, err := s.session.OpenStream(openCtx)
	if err == nil {
		var header [tunnelv1.PeerDeliveryHeaderBytes]byte
		header, err = p.binding.Delivery.Header()
		if err == nil {
			err = stream.SetWriteDeadline(time.Now().Add(streamIntroductionTimeout))
		}
		if err == nil {
			var n int
			n, err = stream.Write(header[:])
			if n != len(header) && err == nil {
				err = io.ErrShortWrite
			}
		}
		if err == nil {
			err = stream.SetWriteDeadline(time.Time{})
		}
	}
	s.mu.Lock()
	valid := s.ctx.Err() == nil && s.pairs[p.binding.Delivery.Pair] == p && p.active == reserved
	if !valid || err != nil {
		if p.active == reserved {
			p.active = nil
		}
		s.mu.Unlock()
		if stream != nil {
			_ = stream.Close()
		}
		if err != nil {
			return nil, err
		}
		return nil, net.ErrClosed
	}
	reserved.StreamCarrier = &StreamCarrier{Conn: stream}
	s.mu.Unlock()
	return reserved, nil
}

func (p *StreamPair) Accept(ctx context.Context) (*SharedStreamCarrier, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.done:
		return nil, net.ErrClosed
	case c := <-p.pending:
		select {
		case <-p.done:
			return nil, net.ErrClosed
		default:
		}
		return c, nil
	}
}

func (p *StreamPair) Close() error {
	s := p.owner
	s.mu.Lock()
	carrier := s.removeLocked(p)
	s.mu.Unlock()
	if carrier != nil {
		_ = carrier.Close()
	}
	p.opens.Wait()
	return nil
}

func (s *SharedStreams) Close() error {
	s.once.Do(func() { s.cancel(); s.wait.Wait(); s.introductions.Wait(); s.opens.Wait() })
	return nil
}

// SharedStreamCarrier validates direction, path, and MAC before sending and
// receiving. closing it removes only the pair's stream, not the outer session.
type SharedStreamCarrier struct {
	*StreamCarrier
	pair   *StreamPair
	first  []byte
	readMu sync.Mutex
	once   sync.Once
}

func (c *SharedStreamCarrier) Send(ctx context.Context, b []byte) error {
	if !c.pair.binding.authentic(b, c.pair.binding.Role) {
		return tunnelv1.ErrPeerPacket
	}
	s := c.pair.owner
	s.mu.Lock()
	valid := s.ctx.Err() == nil && s.pairs[c.pair.binding.Delivery.Pair] == c.pair && c.pair.active == c && c.StreamCarrier != nil
	s.mu.Unlock()
	if !valid {
		return net.ErrClosed
	}
	wire, err := c.pair.binding.Delivery.Seal(tunnelv1.PeerDeliveryStream, c.pair.binding.Key, b)
	if err != nil {
		return err
	}
	return c.StreamCarrier.sendFramed(ctx, func() error {
		return tunnelv1.WritePeerDeliveryFrame(c.StreamCarrier.Conn, wire, tunnelv1.PeerDeliveryStream, c.pair.binding.Key)
	})
}

func (c *SharedStreamCarrier) Receive(ctx context.Context) ([]byte, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	s := c.pair.owner
	s.mu.Lock()
	valid := s.ctx.Err() == nil && s.pairs[c.pair.binding.Delivery.Pair] == c.pair && c.pair.active == c && c.StreamCarrier != nil
	s.mu.Unlock()
	if !valid {
		return nil, net.ErrClosed
	}
	if c.first != nil {
		b := c.first
		c.first = nil
		return b, nil
	}
	stop := interruptOnCancel(ctx, c.Close)
	defer stop()
	d, b, err := tunnelv1.ReadPeerDeliveryFrame(c.StreamCarrier.Conn, tunnelv1.PeerDeliveryStream, c.pair.binding.Key)
	if err != nil {
		return nil, err
	}
	if d != c.pair.binding.Delivery {
		return nil, tunnelv1.ErrPeerPacket
	}
	s.mu.Lock()
	valid = s.ctx.Err() == nil && s.pairs[c.pair.binding.Delivery.Pair] == c.pair && c.pair.active == c
	s.mu.Unlock()
	if !valid {
		return nil, net.ErrClosed
	}
	if !c.pair.binding.authentic(b, 1-c.pair.binding.Role) {
		return nil, tunnelv1.ErrPeerPacket
	}
	s.mu.Lock()
	accepted := s.pairs[c.pair.binding.Delivery.Pair] == c.pair && c.pair.active == c && c.pair.replay.accept(b)
	s.mu.Unlock()
	if !accepted {
		return nil, tunnelv1.ErrPeerPacket
	}
	return b, nil
}

func (c *SharedStreamCarrier) Close() error {
	c.once.Do(func() {
		s := c.pair.owner
		s.mu.Lock()
		if c.pair.active == c {
			c.pair.active = nil
			select {
			case pending := <-c.pair.pending:
				if pending != c {
					c.pair.pending <- pending
				}
			default:
			}
		}
		carrier := c.StreamCarrier
		s.mu.Unlock()
		if carrier != nil {
			_ = carrier.Close()
		}
	})
	return nil
}
