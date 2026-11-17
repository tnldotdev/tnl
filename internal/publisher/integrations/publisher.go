// package integrations maintains project integration services on this machine.
package integrations

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// Snapshot captures one saved service and its local serving operation. a changed
// revision drains that operation before preparing another at the same hostname.
type Snapshot struct {
	Config   publisherservice.RunConfig
	Service  controlv1.Service
	Revision string
	// readiness owns any additional local readiness record, such as an alias's
	// selected service run. false uses a bounded cleanup context during shutdown.
	Readiness func(context.Context, bool) error
}

// Publisher maintains a locally elected integration service run while app
// tunnels run, independently of their own service runs.
type Publisher struct {
	State    *clientstate.Database
	Store    *clientstate.Store
	Server   string
	Hostname string
	Prepare  func(context.Context) (Snapshot, error)
	Eligible func(context.Context) (bool, error)
	Revision func(context.Context) (string, error)
	Report   func(ready bool, err error)
	// run, lock and interval are substituted only by lifecycle tests.
	run      func(context.Context, publisherservice.RunConfig) error
	lock     func() (io.Closer, error)
	interval time.Duration
}

var errIntegrationRunStale = errors.New("integration service run was replaced or stopped")

type integrationAttempt struct {
	operation, cleanup error
	recovered          bool
}

func (a integrationAttempt) Err() error { return errors.Join(a.operation, a.cleanup) }

func integrationStopResult(err error) error {
	if failure.Only(err, context.Canceled) {
		return nil
	}
	return err
}

// Maintain retries unavailable attempts, then returns the final owned shutdown
// result. recovered attempt errors are reported, not retained as shutdown errors.
func (p Publisher) Maintain(ctx context.Context) error {
	interval := p.interval
	if interval == 0 {
		interval = 4 * time.Second
	}
	acquire := p.lock
	if acquire == nil {
		acquire = func() (io.Closer, error) {
			return p.Store.LockHostname("companion:" + p.Hostname)
		}
	}
	var pendingCleanup error
	for ctx.Err() == nil {
		eligible := true
		var operation, cleanup error
		owned := false
		if p.Eligible != nil {
			eligible, operation = p.Eligible(ctx)
		}
		// keep the lock identity stable across tnl versions sharing client state.
		if operation == nil && eligible {
			lock, lockErr := acquire()
			operation = lockErr
			if operation == nil {
				owned = true
				attempt := p.serve(ctx, interval)
				operation = attempt.operation
				if attempt.recovered {
					pendingCleanup = nil
				}
				// serve joins the publisher and clears readiness before releasing ownership.
				cleanup = errors.Join(attempt.cleanup, lock.Close())
				pendingCleanup = errors.Join(pendingCleanup, integrationStopResult(cleanup))
			}
		}
		if ctx.Err() != nil {
			if !owned && failure.Only(operation, clientstate.ErrLocked) {
				operation = nil
			}
			return integrationStopResult(errors.Join(operation, pendingCleanup))
		}
		err := errors.Join(operation, cleanup)
		if err != nil && !failure.Only(err, clientstate.ErrLocked) && p.Report != nil {
			p.Report(false, err)
		}
		select {
		case <-ctx.Done():
			return integrationStopResult(pendingCleanup)
		case <-time.After(interval):
		}
	}
	return integrationStopResult(pendingCleanup)
}

func (p Publisher) serve(parent context.Context, interval time.Duration) integrationAttempt {
	snapshot, err := p.Prepare(parent)
	if err != nil {
		return integrationAttempt{operation: err}
	}
	if snapshot.Service.Id != snapshot.Config.ServiceID || snapshot.Service.Endpoint == nil ||
		snapshot.Service.Endpoint.Hostname != p.Hostname {
		return integrationAttempt{operation: errors.New("prepared integration service has a different service ID or hostname")}
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	publisherInstanceID, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		return integrationAttempt{operation: err}
	}
	var mu sync.Mutex
	ready := false
	config := snapshot.Config
	var readinessErr error
	var binding controlv1.ServiceRunPreparation
	stopped := false
	notified := false
	change := func(ctx context.Context, available bool) error {
		var err error
		if available {
			if ctx.Err() != nil {
				return context.Cause(ctx)
			}
			if stopped || binding.ServiceId == "" || binding.RunNumber < 1 {
				return errIntegrationRunStale
			}
			err = p.State.MarkIntegrationURLReady(ctx, p.Server, p.Hostname, publisherInstanceID, binding.ServiceId, uint64(binding.RunNumber))
		} else {
			err = p.State.ClearIntegrationURLReady(ctx, p.Server, p.Hostname, publisherInstanceID)
		}
		if snapshot.Readiness != nil && (!available || err == nil) {
			err = errors.Join(err, snapshot.Readiness(ctx, available))
		}
		ready = available && err == nil
		return err
	}
	clear := func() error {
		until := time.Now().Add(2 * time.Second)
		if deadline, ok := parent.Deadline(); ok && deadline.Before(until) {
			until = deadline
		}
		// retries must not start the enclosing publication's terminal budget.
		// after that owner stops, its original bound also caps readiness cleanup.
		if parent.Err() != nil && config.ShutdownDeadline != nil {
			if deadline := config.ShutdownDeadline(); !deadline.IsZero() && deadline.Before(until) {
				until = deadline
			}
		}
		cleanupParent := context.WithoutCancel(parent)
		if config.ShutdownContext != nil {
			cleanupParent = config.ShutdownContext
		}
		cleanup, stop := context.WithDeadline(cleanupParent, until)
		defer stop()
		return errors.Join(change(cleanup, false), context.Cause(cleanup))
	}
	prepared, onReady, status := config.Prepared, config.Ready, config.ObserveReadiness
	config.Prepared = func(preparation controlv1.ServiceRunPreparation) error {
		mu.Lock()
		defer mu.Unlock()
		if parent.Err() != nil {
			return context.Cause(parent)
		}
		if stopped || ctx.Err() != nil || preparation.ServiceId != config.ServiceID || preparation.Hostname != p.Hostname ||
			!opaqueid.Valid(preparation.ServiceRunId, opaqueid.ServiceRunPrefix) || preparation.RunNumber < 1 {
			return errIntegrationRunStale
		}
		// Publish owns one prepared run. replacement belongs to a fresh snapshot,
		// so argument-free Ready/status callbacks cannot follow a newer binding.
		if binding.ServiceId != "" {
			if binding.ServiceId == preparation.ServiceId && binding.ServiceRunId == preparation.ServiceRunId && binding.RunNumber == preparation.RunNumber {
				return nil
			}
			return errIntegrationRunStale
		}
		notified = false
		if err := clear(); err != nil {
			return err
		}
		if prepared != nil {
			if err := prepared(preparation); err != nil {
				return err
			}
		}
		binding = preparation
		return nil
	}
	config.Ready = func() error {
		mu.Lock()
		defer mu.Unlock()
		if parent.Err() != nil {
			return context.Cause(parent)
		}
		if stopped || binding.ServiceId == "" || ctx.Err() != nil {
			return errIntegrationRunStale
		}
		err := change(ctx, true)
		if err == nil && onReady != nil {
			err = onReady()
		}
		if err != nil {
			return errors.Join(err, clear())
		}
		notified = true
		if p.Report != nil && parent.Err() == nil {
			p.Report(true, nil)
		}
		return nil
	}
	config.ObserveReadiness = func(state publisherservice.RunStatus) {
		mu.Lock()
		defer mu.Unlock()
		if stopped || binding.ServiceId == "" || state.Ready && ctx.Err() != nil {
			return
		}
		if status != nil {
			status(state)
		}
		if !notified || readinessErr != nil || ready == state.Ready {
			return
		}
		if state.Ready {
			readinessErr = change(ctx, true)
		} else {
			readinessErr = clear()
		}
		if readinessErr != nil {
			cancel()
		} else if p.Report != nil && parent.Err() == nil {
			p.Report(state.Ready, nil)
		}
	}
	run := p.run
	if run == nil {
		run = publisherservice.Publish
	}
	done := make(chan error, 1)
	go func() { done <- run(ctx, config) }()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	finish := func(result error) integrationAttempt {
		mu.Lock()
		defer mu.Unlock()
		stopped = true
		cancel()
		return integrationAttempt{operation: errors.Join(result, readinessErr), cleanup: clear(), recovered: notified}
	}
	stop := func(cause error) integrationAttempt {
		mu.Lock()
		stopped = true
		cancel()
		clearErr := clear()
		mu.Unlock()
		result := <-done
		mu.Lock()
		defer mu.Unlock()
		return integrationAttempt{operation: errors.Join(cause, readinessErr), cleanup: errors.Join(clearErr, result), recovered: notified}
	}
	for {
		select {
		case <-parent.Done():
			return stop(nil)
		case err := <-done:
			return finish(err)
		case <-ticker.C:
			mu.Lock()
			var renewErr error
			if ready {
				renewErr = p.State.MarkIntegrationURLReady(ctx, p.Server, p.Hostname, publisherInstanceID, binding.ServiceId, uint64(binding.RunNumber))
			}
			mu.Unlock()
			if renewErr != nil {
				return stop(renewErr)
			}
			if p.Revision != nil {
				revision, err := p.Revision(ctx)
				if err != nil || revision != snapshot.Revision {
					return stop(err)
				}
			}
		}
	}
}
