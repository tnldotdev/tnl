package connector

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestConnectionSDKPeerReservationPreservesFailureForDelayedWaiter(t *testing.T) {
	f := newSDKFixture(t, true)
	delayed, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	resolve := f.operations.resolve
	f.operations.resolve = func(ctx context.Context, options ContextOptions) (connectorruntime.Context, error) {
		if ctx == delayed {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return connectorruntime.Context{}, ctx.Err()
			}
		}
		return resolve(ctx, options)
	}
	finished := make(chan struct{})
	result := make(chan error, 1)
	var once sync.Once
	defer func() { once.Do(func() { close(release) }); <-finished }()
	go func() {
		defer close(finished)
		_, err := f.prepare(delayed, "first", "db")
		result <- err
	}()
	select {
	case <-entered:
	case <-delayed.Done():
		t.Fatal("waiter did not reach context resolution", delayed.Err())
	}
	// the held request has already recorded its start time. fail another request
	// for the same identity, then reserve a peer before letting the waiter select.
	f.denyStart = true
	if _, err := f.prepare(t.Context(), "first", "db"); !errors.Is(err, connectorruntime.ErrUnauthorized) || Reason(err) != failure.ConnectionHandleInvalid {
		t.Fatal("startup denial lost its owned classification", err)
	}
	f.denyStart = false
	peer, err := f.prepare(t.Context(), "other", "db")
	if err != nil {
		t.Fatal("peer could not start beside a recent failure", err)
	}
	once.Do(func() { close(release) })
	if err := <-result; !errors.Is(err, connectorruntime.ErrUnavailable) || Reason(err) != failure.ConnectionHandleInvalid {
		t.Error("delayed waiter did not observe the completed startup failure", err)
	}
	<-finished
	if f.started != 2 {
		t.Fatalf("peer reservation erased a recent failure: got %d startups, want 2", f.started)
	}
	// retaining the observation for old requests must not block an explicit later
	// retry of this identity or replace the unrelated peer.
	current, err := f.prepare(t.Context(), "first", "db")
	if err != nil || f.started != 3 || current.Owner.ConnectionHandle == peer.Owner.ConnectionHandle {
		t.Fatal("an explicit later request could not retry independently", err, f.started)
	}
	warm, err := f.prepare(t.Context(), "other", "sibling")
	if err != nil || warm.Owner.ConnectionHandle != peer.Owner.ConnectionHandle || f.stopped != 0 {
		t.Fatal("failed identity retry affected its peer", err, f.stopped)
	}
}

func TestConnectionSDKFailureReclamationUsesCompletionTime(t *testing.T) {
	for _, test := range []struct {
		name         string
		age          time.Duration
		startFailure bool
		retained     bool
		wantPresent  bool
	}{
		{name: "recent startup", age: time.Second, startFailure: true, wantPresent: true},
		{name: "expired startup", age: sdkRequestLifetime + time.Second, startFailure: true},
		{name: "retained startup", age: sdkRequestLifetime + time.Second, startFailure: true, retained: true, wantPresent: true},
		{name: "recent cleanup", age: time.Second, wantPresent: true},
		{name: "expired cleanup", age: sdkRequestLifetime + time.Second},
		{name: "retention applies only to startup", age: sdkRequestLifetime + time.Second, retained: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newSDKFixture(t, false)
			f.options.RetainStartFailure = test.retained
			key := sdkDigest("completed failure")
			record := sdkOwnerRecord{Failure: failure.ConnectionHandleInvalid, FinishedAt: time.Now().Add(-test.age), StartFailure: test.startFailure}
			if err := sdkUpdate(t.Context(), f.options, func(r *sdkRegistry) error {
				r.Owners[key] = record
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.prepare(t.Context(), "", "db"); err != nil {
				t.Fatal("peer reservation failed", err)
			}
			if err := sdkUpdate(t.Context(), f.options, func(r *sdkRegistry) error {
				current, present := r.Owners[key]
				if present != test.wantPresent {
					t.Errorf("failure present = %t, want %t (finished %s ago)", present, test.wantPresent, test.age)
				}
				if present && (current.Failure != record.Failure || !current.FinishedAt.Equal(record.FinishedAt) || current.StartFailure != record.StartFailure) {
					t.Error("peer reservation changed the completed failure")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
