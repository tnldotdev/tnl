// package integrationurls maintains project integration URLs on the publisher's machine.
package integrationurls

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
)

// Snapshot is immutable for one integration URL publish run. a changed revision
// drains that run before starting another against the same saved hostname.
type Snapshot struct {
	Config   publisher.Config
	Revision string
}

// Publisher maintains a locally elected publish run for an integration URL
// while app tunnels run, independently of their own publish runs.
type Publisher struct {
	State    *clientstate.Database
	Store    *clientstate.Store
	Server   string
	Hostname string
	Prepare  func(context.Context) (Snapshot, error)
	Revision func(context.Context) (string, error)
	Report   func(publisher.Event, error)
	// run and interval are substituted only by lifecycle tests.
	run      func(context.Context, publisher.Config) error
	interval time.Duration
}

func (p Publisher) Maintain(ctx context.Context) {
	interval := p.interval
	if interval == 0 {
		interval = 4 * time.Second
	}
	for ctx.Err() == nil {
		// keep the lock identity stable across tnl versions sharing client state.
		lock, err := p.Store.LockHostname("companion:" + p.Hostname)
		if err == nil {
			err = p.serve(ctx, interval)
			// serve joins the publisher and clears readiness before releasing ownership.
			err = errors.Join(err, lock.Close())
		}
		if err != nil && !errors.Is(err, clientstate.ErrLocked) && ctx.Err() == nil && p.Report != nil {
			p.Report(publisher.Event{}, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func (p Publisher) serve(parent context.Context, interval time.Duration) error {
	snapshot, err := p.Prepare(parent)
	if err != nil {
		return err
	}
	if snapshot.Config.Hostname != p.Hostname {
		return errors.New("prepared integration URL publisher has a different hostname")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	publisherInstanceID, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		return err
	}
	var mu sync.Mutex
	ready := false
	clear := func() error {
		cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		return p.State.ClearIntegrationURLReady(cleanup, p.Server, p.Hostname, publisherInstanceID)
	}
	config := snapshot.Config
	config.Observe = func(event publisher.Event) error {
		mu.Lock()
		defer mu.Unlock()
		var observeErr error
		switch event.Type {
		case publisher.EventReady:
			observeErr = p.State.MarkIntegrationURLReady(ctx, p.Server, p.Hostname, publisherInstanceID)
			ready = observeErr == nil
		case publisher.EventProvisioning, publisher.EventDraining:
			ready = false
			observeErr = clear()
		default:
			return nil
		}
		if p.Report != nil && parent.Err() == nil && observeErr == nil {
			p.Report(event, nil)
		}
		return observeErr
	}
	run := p.run
	if run == nil {
		run = publisher.Run
	}
	done := make(chan error, 1)
	go func() { done <- run(ctx, config) }()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	finish := func(result error) error {
		mu.Lock()
		defer mu.Unlock()
		ready = false
		return errors.Join(result, clear())
	}
	stop := func(cause error) error {
		cancel()
		return finish(errors.Join(cause, <-done))
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
				renewErr = p.State.MarkIntegrationURLReady(ctx, p.Server, p.Hostname, publisherInstanceID)
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
