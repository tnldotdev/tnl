package peer

import (
	"context"
	"net"
	"sync"
)

// CarrierSlot keeps a logical path alive while its delivery carrier is being
// prepared or replaced. role owners install only authorized carriers. slow ICE,
// NAT changes, and relay reconnects therefore do not replace the inner QUIC
// session. peer probes still validate each installed carrier before selection.
type CarrierSlot struct {
	mu       sync.Mutex
	current  Carrier
	revision uint64
	changed  chan struct{}
	closed   bool
}

func NewCarrierSlot() *CarrierSlot { return &CarrierSlot{changed: make(chan struct{})} }

// Install transfers ownership, including when shutdown raced preparation. closing
// the old carrier interrupts its receive without holding the slot's mutex.
func (s *CarrierSlot) Install(next Carrier) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		if next != nil {
			_ = next.Close()
		}
		return net.ErrClosed
	}
	old := s.current
	s.current = next
	s.notifyLocked()
	s.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	return nil
}

func (s *CarrierSlot) notifyLocked() {
	s.revision++
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *CarrierSlot) retire(revision uint64) {
	s.mu.Lock()
	if s.revision != revision {
		s.mu.Unlock()
		return
	}
	old := s.current
	s.current = nil
	s.notifyLocked()
	s.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
}

func (s *CarrierSlot) Send(ctx context.Context, b []byte) error {
	return s.SendGeneration(ctx, b, s.Generation())
}

func (s *CarrierSlot) Generation() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revision
}

func (s *CarrierSlot) SendGeneration(ctx context.Context, b []byte, expected uint64) error {
	s.mu.Lock()
	c, revision, closed := s.current, s.revision, s.closed
	s.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if c == nil {
		return nil
	}
	if revision != expected {
		return nil
	}
	if err := c.Send(ctx, b); err != nil {
		s.retire(revision)
	}
	// delivery loss while a carrier recovers is recovered by inner QUIC. no
	// application writes are buffered or replayed by this slot.
	return nil
}

func (s *CarrierSlot) Receive(ctx context.Context) ([]byte, error) {
	for {
		s.mu.Lock()
		c, revision, changed, closed := s.current, s.revision, s.changed, s.closed
		s.mu.Unlock()
		if closed {
			return nil, net.ErrClosed
		}
		if c == nil {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-changed:
				continue
			}
		}
		b, err := c.Receive(ctx)
		if err != nil {
			s.retire(revision)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		s.mu.Lock()
		current := s.revision == revision && !s.closed
		s.mu.Unlock()
		if current {
			return b, nil
		}
	}
}

func (s *CarrierSlot) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	old := s.current
	s.current = nil
	s.notifyLocked()
	s.mu.Unlock()
	if old != nil {
		return old.Close()
	}
	return nil
}
