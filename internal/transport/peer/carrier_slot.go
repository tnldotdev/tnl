package peer

import (
	"context"
	"net"
	"sync"
)

// CarrierSlot owns replaceable delivery for one already-authorized logical path.
// the role owner supplies authority and deadlines; replacement never changes
// either. a missing carrier drops output while inner QUIC recovers its packets.
type CarrierSlot struct {
	replace  sync.Mutex
	mu       sync.Mutex
	current  *installedCarrier
	revision uint64
	changed  chan struct{}
	closed   bool
	once     sync.Once
	err      error
}

type installedCarrier struct {
	carrier Carrier
	ctx     context.Context
	cancel  context.CancelFunc
	work    sync.WaitGroup
}

// carrierRevision is a local admission token, not a wire delivery generation.
// the slot identity prevents an equal counter from authorizing another path.
type carrierRevision struct {
	slot     *CarrierSlot
	revision uint64
}

// copyTo commits input under the same lock that fences carrier replacement.
// the zero token belongs to an endpoint path with a non-replaceable carrier.
func (r carrierRevision) copyTo(destination, source []byte) (int, bool) {
	if r.slot != nil {
		r.slot.mu.Lock()
		defer r.slot.mu.Unlock()
		if r.slot.closed || r.slot.current == nil || r.slot.revision != r.revision {
			return 0, false
		}
	}
	return copy(destination, source), true
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

// Install transfers ownership even when shutdown wins. removal fences new work
// before canceling and joining entered calls. no caller holds a role-state lock
// while installing a carrier.
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
	s.notifyLocked()
	s.mu.Unlock()
	_ = old.close()
	// do not publish the successor until every entered predecessor call joined.
	// Close can fence this installation while physical cleanup is outstanding.
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		if next != nil {
			_ = next.Close()
		}
		return net.ErrClosed
	}
	if next != nil {
		ctx, cancel := context.WithCancel(context.Background())
		s.current = &installedCarrier{carrier: next, ctx: ctx, cancel: cancel}
		s.notifyLocked()
	}
	s.mu.Unlock()
	return nil
}

func (s *CarrierSlot) notifyLocked() {
	s.revision++
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *CarrierSlot) retire(revision carrierRevision) {
	s.replace.Lock()
	defer s.replace.Unlock()
	s.mu.Lock()
	if s.closed || revision.slot != s || s.revision != revision.revision {
		s.mu.Unlock()
		return
	}
	old := s.current
	s.current = nil
	s.notifyLocked()
	s.mu.Unlock()
	_ = old.close()
}

// Generation returns an opaque local revision for observation and admission.
// it is independent of the authenticated wire delivery generation.
func (s *CarrierSlot) Generation() carrierRevision {
	s.mu.Lock()
	defer s.mu.Unlock()
	return carrierRevision{slot: s, revision: s.revision}
}

// enter and retirement share the lock; work cannot be added after removal.
func (s *CarrierSlot) enter(ctx context.Context, revision carrierRevision) (*installedCarrier, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if revision.slot != s {
		return nil, ErrConfiguration
	}
	if s.closed {
		return nil, net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.current == nil || s.revision != revision.revision {
		return nil, nil
	}
	s.current.work.Add(1)
	return s.current, nil
}

// trackForward joins an entered publisher write without canceling it when its
// source is removed. the caller retains its original timeout and authority.
func (s *CarrierSlot) trackForward(ctx context.Context, revision carrierRevision) (func(), error) {
	c, err := s.enter(ctx, revision)
	if c == nil {
		return nil, err
	}
	return sync.OnceFunc(c.work.Done), nil
}

func (s *CarrierSlot) Send(ctx context.Context, b []byte) error {
	return s.sendRevision(ctx, b, s.Generation())
}

func (s *CarrierSlot) sendRevision(ctx context.Context, b []byte, revision carrierRevision) error {
	c, err := s.enter(ctx, revision)
	if c == nil {
		return err
	}
	call, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctx, cancel)
	err = c.carrier.Send(call, b)
	stop()
	cancel()
	c.work.Done()
	if err != nil {
		s.retire(revision)
	}
	return nil
}

func (s *CarrierSlot) Receive(ctx context.Context) ([]byte, error) {
	b, _, err := s.receiveRevision(ctx)
	return b, err
}

func (s *CarrierSlot) receiveRevision(ctx context.Context) ([]byte, carrierRevision, error) {
	for {
		s.mu.Lock()
		revision, changed := carrierRevision{slot: s, revision: s.revision}, s.changed
		s.mu.Unlock()
		c, err := s.enter(ctx, revision)
		if err != nil {
			return nil, carrierRevision{}, err
		}
		if c == nil {
			select {
			case <-ctx.Done():
				return nil, carrierRevision{}, ctx.Err()
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
			continue
		}
		s.mu.Lock()
		current := !s.closed && s.revision == revision.revision
		s.mu.Unlock()
		if current {
			return b, revision, nil
		}
	}
}

func (s *CarrierSlot) Close() error {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		old := s.current
		s.current = nil
		s.notifyLocked()
		s.mu.Unlock()
		// fence dispatch before joining a concurrent replacement's cleanup.
		s.replace.Lock()
		s.err = old.close()
		s.replace.Unlock()
	})
	return s.err
}
