package identity

import (
	"context"
	"errors"
	"time"
)

type applicationSessionFence struct {
	deadline time.Time
	denied   bool
	changed  chan struct{}
}

func (s *ApplicationSession) publishFence(deadline time.Time, denied bool) {
	s.fenceMu.Lock()
	defer s.fenceMu.Unlock()
	previous := s.fence.Swap(&applicationSessionFence{deadline: deadline, denied: denied, changed: make(chan struct{})})
	if previous != nil {
		close(previous.changed)
	}
}

// advanceFence rechecks the original confirmation boundary while holding the
// timer fence lock. a late storage return cannot revive a worker already fenced.
func (s *ApplicationSession) advanceFence(ctx context.Context, deadline, confirmationDeadline time.Time) error {
	s.fenceMu.Lock()
	defer s.fenceMu.Unlock()
	if err := context.Cause(ctx); err != nil {
		return errors.Join(ErrApplicationSessionUncertain, err)
	}
	if !time.Now().Before(confirmationDeadline) {
		return errors.Join(ErrApplicationSessionUncertain, ErrScope)
	}
	previous := s.fence.Load()
	if previous != nil && (previous.denied || !time.Now().Before(previous.deadline)) {
		return errors.Join(ErrApplicationSessionUncertain, ErrScope)
	}
	s.fence.Store(&applicationSessionFence{deadline: deadline, changed: make(chan struct{})})
	if previous != nil {
		close(previous.changed)
	}
	return nil
}

// CheckServing uses only a durably confirmed fence, not a response still waiting
// for storage or a server heartbeat that outlived the local confirmation.
func (s *ApplicationSession) CheckServing() error {
	fence := s.fence.Load()
	if fence == nil || fence.denied || !time.Now().Before(fence.deadline) {
		return ErrScope
	}
	return nil
}

// Run owns and joins the credential deadline watcher around the existing
// publication worker. it is not a second publisher or cleanup lifecycle.
func (s *ApplicationSession) Run(ctx context.Context, run func(context.Context) error) error {
	owned, cancel := context.WithCancelCause(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			s.fenceMu.Lock()
			fence := s.fence.Load()
			if fence == nil || fence.denied || !time.Now().Before(fence.deadline) {
				cancel(ErrScope)
				s.fenceMu.Unlock()
				return
			}
			s.fenceMu.Unlock()
			timer := time.NewTimer(time.Until(fence.deadline))
			select {
			case <-owned.Done():
				timer.Stop()
				return
			case <-fence.changed:
				timer.Stop()
			case <-timer.C:
				s.fenceMu.Lock()
				if s.fence.Load() != fence {
					s.fenceMu.Unlock()
					continue
				}
				cancel(ErrScope)
				s.fenceMu.Unlock()
				return
			}
		}
	}()
	result := run(owned)
	cause := context.Cause(owned)
	cancel(nil)
	<-done
	return errors.Join(result, cause)
}
