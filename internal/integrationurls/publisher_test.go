package integrationurls

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/publisher"
)

const testPublisherServer = "https://control.example.test"
const testPublisherHost = "integration.project.example.test"

func integrationURLState(t *testing.T) *clientstate.Database {
	t.Helper()
	state, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	return state
}

func waitIntegrationURLPublisher[T any](t *testing.T, channel <-chan T) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("integration URL publisher did not finish")
		var zero T
		return zero
	}
}

func TestIntegrationURLPublisherHandoffWaitsForOldRunCleanup(t *testing.T) {
	state := integrationURLState(t)
	store, err := state.Server(t.Context(), testPublisherServer)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 1)
	draining := make(chan struct{}, 1)
	release := make(chan struct{})
	worker := Publisher{State: state, Store: store, Server: testPublisherServer, Hostname: testPublisherHost, interval: time.Millisecond,
		Prepare: func(context.Context) (Snapshot, error) {
			return Snapshot{Config: publisher.Config{Hostname: testPublisherHost}}, nil
		},
		run: func(ctx context.Context, config publisher.Config) error {
			if err := config.Observe(publisher.Event{Type: publisher.EventReady}); err != nil {
				return err
			}
			started <- struct{}{}
			<-ctx.Done()
			if err := config.Observe(publisher.Event{Type: publisher.EventDraining}); err != nil {
				return err
			}
			draining <- struct{}{}
			<-release
			return nil
		},
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); worker.Maintain(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-release:
		default:
			close(release)
		}
		waitIntegrationURLPublisher(t, done)
	})
	waitIntegrationURLPublisher(t, started)
	ready, err := state.IntegrationURLReady(t.Context(), testPublisherServer, testPublisherHost)
	if err != nil || !ready {
		t.Fatal("ready publisher was not announced")
	}
	cancel()
	waitIntegrationURLPublisher(t, draining)
	ready, err = state.IntegrationURLReady(t.Context(), testPublisherServer, testPublisherHost)
	if err != nil || ready {
		t.Fatal("draining publisher retained readiness")
	}
	if lock, err := store.LockHostname("companion:" + testPublisherHost); err == nil {
		_ = lock.Close()
		t.Fatal("ownership released while the old publisher was draining")
	}
	close(release)
	waitIntegrationURLPublisher(t, done)
	lock, err := store.LockHostname("companion:" + testPublisherHost)
	if err != nil {
		t.Fatalf("ownership remained locked after cleanup: %v", err)
	}
	_ = lock.Close()
}

func TestIntegrationURLPublisherReprovisioningClearsReadiness(t *testing.T) {
	state := integrationURLState(t)
	store, err := state.Server(t.Context(), testPublisherServer)
	if err != nil {
		t.Fatal(err)
	}
	checked := make(chan bool, 1)
	ctx, cancel := context.WithCancel(t.Context())
	worker := Publisher{State: state, Store: store, Server: testPublisherServer, Hostname: testPublisherHost, interval: time.Millisecond,
		Prepare: func(context.Context) (Snapshot, error) {
			return Snapshot{Config: publisher.Config{Hostname: testPublisherHost}}, nil
		},
		run: func(ctx context.Context, config publisher.Config) error {
			if err := config.Observe(publisher.Event{Type: publisher.EventReady}); err != nil {
				return err
			}
			if err := config.Observe(publisher.Event{Type: publisher.EventProvisioning}); err != nil {
				return err
			}
			ready, err := state.IntegrationURLReady(ctx, testPublisherServer, testPublisherHost)
			if err != nil {
				return err
			}
			checked <- ready
			<-ctx.Done()
			return nil
		},
	}
	done := make(chan struct{})
	go func() { defer close(done); worker.Maintain(ctx) }()
	t.Cleanup(func() { cancel(); waitIntegrationURLPublisher(t, done) })
	if waitIntegrationURLPublisher(t, checked) {
		t.Fatal("reprovisioning retained readiness of the old run")
	}
}

func TestIntegrationURLPublisherFailureRetriesWithoutRetainingReadiness(t *testing.T) {
	state := integrationURLState(t)
	store, err := state.Server(t.Context(), testPublisherServer)
	if err != nil {
		t.Fatal(err)
	}
	var runs atomic.Int32
	second := make(chan bool, 1)
	ctx, cancel := context.WithCancel(t.Context())
	worker := Publisher{State: state, Store: store, Server: testPublisherServer, Hostname: testPublisherHost, interval: time.Millisecond,
		Prepare: func(context.Context) (Snapshot, error) {
			return Snapshot{Config: publisher.Config{Hostname: testPublisherHost}}, nil
		},
		run: func(ctx context.Context, config publisher.Config) error {
			if runs.Add(1) == 1 {
				if err := config.Observe(publisher.Event{Type: publisher.EventReady}); err != nil {
					return err
				}
				return errors.New("publisher stopped unexpectedly")
			}
			ready, err := state.IntegrationURLReady(ctx, testPublisherServer, testPublisherHost)
			if err != nil {
				return err
			}
			second <- ready
			<-ctx.Done()
			return nil
		},
	}
	done := make(chan struct{})
	go func() { defer close(done); worker.Maintain(ctx) }()
	t.Cleanup(func() { cancel(); waitIntegrationURLPublisher(t, done) })
	if waitIntegrationURLPublisher(t, second) {
		t.Fatal("failed publisher's readiness survived a retry")
	}
}

func TestIntegrationURLPublisherRevisionChangeJoinsOldRunBeforePreparingAnother(t *testing.T) {
	state := integrationURLState(t)
	store, err := state.Server(t.Context(), testPublisherServer)
	if err != nil {
		t.Fatal(err)
	}
	var revision atomic.Int32
	var prepares atomic.Int32
	started := make(chan struct{}, 2)
	draining := make(chan struct{}, 1)
	release := make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	worker := Publisher{State: state, Store: store, Server: testPublisherServer, Hostname: testPublisherHost, interval: time.Millisecond,
		Prepare: func(context.Context) (Snapshot, error) {
			prepares.Add(1)
			return Snapshot{Config: publisher.Config{Hostname: testPublisherHost}, Revision: fmt.Sprint(revision.Load())}, nil
		},
		Revision: func(context.Context) (string, error) { return fmt.Sprint(revision.Load()), nil },
		run: func(ctx context.Context, config publisher.Config) error {
			started <- struct{}{}
			<-ctx.Done()
			if prepares.Load() == 1 {
				draining <- struct{}{}
				<-release
			}
			return nil
		},
	}
	done := make(chan struct{})
	go func() { defer close(done); worker.Maintain(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-release:
		default:
			close(release)
		}
		waitIntegrationURLPublisher(t, done)
	})
	waitIntegrationURLPublisher(t, started)
	revision.Store(1)
	waitIntegrationURLPublisher(t, draining)
	if prepares.Load() != 1 {
		t.Fatal("new run was prepared before the old run drained")
	}
	close(release)
	waitIntegrationURLPublisher(t, started)
	if prepares.Load() != 2 {
		t.Fatalf("prepared %d times, want once per run", prepares.Load())
	}
}
