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
	replace   sync.Mutex
	mu        sync.Mutex
	current   *installedCarrier
	revision  uint64
	changed   chan struct{}
	closed    bool
	closeOnce sync.Once
	closeErr  error
}

// registration and work entry share the slot lock. retirement removes the
// registration first, then interrupts and joins entered carrier calls unlocked.
type installedCarrier struct {
	carrier Carrier
	ctx     context.Context
	cancel  context.CancelFunc
	work    sync.WaitGroup
}

func (c *installedCarrier) close() error {
	if c == nil {
		return nil
	}
	c.cancel()
	err := c.carrier.Close()
	c.work.Wait()
	return err
}

func NewCarrierSlot() *CarrierSlot { return &CarrierSlot{changed: make(chan struct{})} }

// Install transfers ownership, including when shutdown raced preparation. the
// revision change cuts uncommitted endpoint reads and future old-carrier sends.
// entered calls are interrupted and joined without holding the slot's data lock.
// this changes delivery only; the caller must retain the exact peer authority.
func (s *CarrierSlot) Install(next Carrier) error {
	s.replace.Lock()
	defer s.replace.Unlock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		if next != nil {
			_ = next.Close()
		}
		return net.ErrClosed
	}
	old := s.current
	s.current = nil
	if next != nil {
		ctx, cancel := context.WithCancel(context.Background())
		s.current = &installedCarrier{carrier: next, ctx: ctx, cancel: cancel}
	}
	s.notifyLocked()
	s.mu.Unlock()
	_ = old.close()
	return nil
}

func (s *CarrierSlot) notifyLocked() {
	s.revision++
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *CarrierSlot) retire(revision uint64) {
	s.replace.Lock()
	defer s.replace.Unlock()
	s.mu.Lock()
	if s.revision != revision || s.closed {
		s.mu.Unlock()
		return
	}
	old := s.current
	s.current = nil
	s.notifyLocked()
	s.mu.Unlock()
	_ = old.close()
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
	if !closed && c != nil && revision == expected && ctx.Err() == nil {
		c.work.Add(1)
	} else {
		c = nil
	}
	s.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	if c == nil {
		return ctx.Err()
	}
	// cancel an entered send when this registration loses its slot, even if
	// the underlying shared carrier's Close does not close its borrowed socket.
	call, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctx, cancel)
	err := c.carrier.Send(call, b)
	stop()
	cancel()
	c.work.Done()
	if err != nil {
		s.retire(revision)
	}
	// delivery loss while a carrier recovers is recovered by inner QUIC. no
	// application writes are buffered or replayed by this slot.
	return nil
}

func (s *CarrierSlot) Receive(ctx context.Context) ([]byte, error) {
	b, _, err := s.receiveGeneration(ctx)
	return b, err
}

// receiveGeneration retains the physical registration across authentication and
// reassembly. only the endpoint's final caller-buffer copy commits packet input.
func (s *CarrierSlot) receiveGeneration(ctx context.Context) ([]byte, uint64, error) {
	for {
		s.mu.Lock()
		c, revision, changed, closed := s.current, s.revision, s.changed, s.closed
		if !closed && c != nil && ctx.Err() == nil {
			c.work.Add(1)
		} else {
			c = nil
		}
		s.mu.Unlock()
		if closed {
			return nil, 0, net.ErrClosed
		}
		if c == nil {
			if err := ctx.Err(); err != nil {
				return nil, 0, err
			}
			select {
			case <-ctx.Done():
				return nil, 0, ctx.Err()
			case <-changed:
				continue
			}
		}
		call, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(c.ctx, cancel)
		b, err := c.carrier.Receive(call)
		stop()
		cancel()
		c.work.Done()
		if err != nil {
			s.retire(revision)
			if ctx.Err() != nil {
				return nil, 0, ctx.Err()
			}
			continue
		}
		s.mu.Lock()
		current := s.revision == revision && !s.closed
		s.mu.Unlock()
		if current {
			return b, revision, nil
		}
	}
}

func (s *CarrierSlot) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		old := s.current
		s.current = nil
		s.notifyLocked()
		s.mu.Unlock()
		// a concurrent install may still be joining its predecessor. close
		// fences dispatch above before waiting for that replacement to finish.
		s.replace.Lock()
		s.closeErr = old.close()
		s.replace.Unlock()
	})
	return s.closeErr
}
