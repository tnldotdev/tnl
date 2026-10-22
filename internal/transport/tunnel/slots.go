package tunnel

import (
	"context"
	"errors"
	"sync"
	"time"
)

// SlotSession owns one authenticated path. Serve must return when its context
// ends or Close is called. a path never owns retries of application streams.
type SlotSession interface {
	Serve(context.Context) error
	Close() error
}

type SlotConnect func(context.Context, uint8, bool) (SlotSession, error)

// ErrRotateSession retires a reusable session's admissions while its existing
// streams drain. the replacement is independent; no live stream is moved.
var ErrRotateSession = errors.New("tunnel: rotate session")

// ErrAwaitAssignment stops pre-claim attempts until Set installs a new key.
// an expired credential is not permission to reclaim a used assignment.
var ErrAwaitAssignment = errors.New("tunnel: wait for a new assignment")

type SlotsConfig struct {
	Connect SlotConnect
	// claimed assignments are single-use. after a serving path fails, wait
	// for a new assignment instead of trying to reclaim the old connection.
	SingleUse              bool
	BackoffMin, BackoffMax time.Duration
	// adapters may distinguish a normal serving exit from transport loss.
	// the default prefers TCP after any QUIC session ends.
	PreferTCPAfter func(SlotSession, error) bool
	// readiness is removed and the session is closed before this callback.
	SessionEnded func(uint8, SlotSession, error)
}

type slotWorker struct {
	key     string
	cancel  context.CancelFunc
	session SlotSession
	ready   bool
}

// Slots maintains two independent paths for either tunnel role. assignment
// keys contain only identity/revision, never credentials or mutable readiness.
// Set replaces only the changed path; first readiness requires both paths.
type Slots struct {
	ctx       context.Context
	config    SlotsConfig
	mu        sync.Mutex
	workers   [2]*slotWorker
	preferTCP [2]bool
	changed   chan struct{}
	closed    bool
	draining  bool
	group     sync.WaitGroup
}

func NewSlots(ctx context.Context, config SlotsConfig) (*Slots, error) {
	if ctx == nil || config.Connect == nil {
		return nil, errors.New("tunnel: slot context and connector are required")
	}
	if config.BackoffMin == 0 {
		config.BackoffMin = 250 * time.Millisecond
	}
	if config.BackoffMax == 0 {
		config.BackoffMax = 10 * time.Second
	}
	if config.BackoffMin <= 0 || config.BackoffMax < config.BackoffMin {
		return nil, errors.New("tunnel: invalid slot backoff")
	}
	return &Slots{ctx: ctx, config: config, changed: make(chan struct{})}, nil
}

func (s *Slots) Set(slot uint8, key string) error {
	if slot > 1 || key == "" {
		return errors.New("tunnel: slot and assignment key are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.draining {
		return errors.New("tunnel: slots closed or draining")
	}
	if old := s.workers[slot]; old != nil {
		if old.key == key {
			return nil
		}
		// control can replace an assignment before its QUIC failure reaches
		// Serve. keep that replacement's transport preference in the slot.
		if transport, ok := old.session.(interface{ Transport() Transport }); old.ready && ok {
			s.preferTCP[slot] = transport.Transport() == TransportQUIC
		}
		old.cancel()
	}
	ctx, cancel := context.WithCancel(s.ctx)
	w := &slotWorker{key: key, cancel: cancel}
	s.workers[slot] = w
	s.notifyLocked()
	s.group.Go(func() { s.run(ctx, slot, w) })
	return nil
}

func (s *Slots) run(ctx context.Context, slot uint8, w *slotWorker) {
	backoff := s.config.BackoffMin
	for ctx.Err() == nil {
		s.mu.Lock()
		if s.closed || s.draining {
			s.mu.Unlock()
			return
		}
		preferTCP := s.preferTCP[slot]
		s.mu.Unlock()
		session, err := s.config.Connect(ctx, slot, preferTCP)
		if err == nil && session != nil {
			s.mu.Lock()
			current := s.workers[slot] == w && !s.closed && !s.draining && ctx.Err() == nil
			if current {
				w.session, w.ready = session, true
				if transport, ok := session.(interface{ Transport() Transport }); ok && transport.Transport() == TransportTLSTCP {
					s.preferTCP[slot] = false
				}
				s.notifyLocked()
			}
			s.mu.Unlock()
			if !current {
				_ = session.Close()
				return
			}
			closeOwned := sync.OnceFunc(func() { _ = session.Close() })
			stop := context.AfterFunc(ctx, closeOwned)
			serveErr := session.Serve(ctx)
			stop()
			rotate := !s.config.SingleUse && ctx.Err() == nil && errors.Is(serveErr, ErrRotateSession)
			s.mu.Lock()
			w.ready, w.session = false, nil
			if s.workers[slot] == w {
				// a failed QUIC path gives TLS/TCP the first attempt on its
				// replacement. successful TCP recovery restores QUIC-first.
				if !rotate {
					if s.config.PreferTCPAfter != nil {
						s.preferTCP[slot] = s.config.PreferTCPAfter(session, serveErr)
					} else if transport, ok := session.(interface{ Transport() Transport }); ok {
						s.preferTCP[slot] = transport.Transport() == TransportQUIC
					}
				}
				s.notifyLocked()
			}
			s.mu.Unlock()
			if rotate {
				s.group.Go(func() {
					if drain, ok := session.(interface{ Drain(context.Context) error }); ok {
						_ = drain.Drain(ctx)
					}
					closeOwned()
				})
			} else {
				closeOwned()
			}
			if s.config.SessionEnded != nil {
				s.config.SessionEnded(slot, session, serveErr)
			}
			if s.config.SingleUse {
				return
			}
			if rotate {
				continue
			}
			backoff = s.config.BackoffMin
		}
		if errors.Is(err, ErrAwaitAssignment) || IsTerminalHandshakeError(err) {
			return
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff = min(2*backoff, s.config.BackoffMax)
	}
}

// Snapshot returns only current ready paths and a wakeup for any state change.
// callers must still handle a path closing between selection and stream open.
func (s *Slots) Snapshot() ([2]SlotSession, <-chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var sessions [2]SlotSession
	for slot, w := range s.workers {
		if !s.draining && !s.closed && w != nil && w.ready {
			sessions[slot] = w.session
		}
	}
	return sessions, s.changed
}

func (s *Slots) notifyLocked() { close(s.changed); s.changed = make(chan struct{}) }

// StopAdmissions cancels pending handshakes and waits for each ready path's
// drain acknowledgement, keeping its transport open for admitted visitors.
// the role owning those visitors decides when to Close the paths afterward.
func (s *Slots) StopAdmissions(ctx context.Context) error {
	s.mu.Lock()
	if s.closed || s.draining {
		s.mu.Unlock()
		return nil
	}
	s.draining = true
	var sessions [2]SlotSession
	for slot, w := range s.workers {
		if w != nil && w.ready {
			sessions[slot] = w.session
		} else if w != nil {
			w.cancel()
		}
	}
	s.notifyLocked()
	s.mu.Unlock()
	var group sync.WaitGroup
	var results [2]error
	for slot, session := range sessions {
		if drain, ok := session.(interface{ Drain(context.Context) error }); ok {
			group.Go(func() {
				results[slot] = drain.Drain(ctx)
			})
		}
	}
	group.Wait()
	return errors.Join(results[:]...)
}

// Drain stops admission, closes and joins both paths. cancellation/revocation
// uses Close for immediate teardown without a drain acknowledgement.
func (s *Slots) Drain(ctx context.Context) error {
	return errors.Join(s.StopAdmissions(ctx), s.Close())
}

func (s *Slots) Close() error {
	s.mu.Lock()
	s.closed = true
	for _, w := range s.workers {
		if w != nil {
			w.cancel()
		}
	}
	s.notifyLocked()
	s.mu.Unlock()
	s.group.Wait()
	return nil
}
