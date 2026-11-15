package integrations

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const testPublisherServer = "https://control.example.test"
const testPublisherHost = "integration.project.example.test"

type integrationPublisherFixture struct {
	service controlv1.Service
	journal *clientstate.Tunnel
	runs    atomic.Int64
}

func newIntegrationPublisherFixture(t *testing.T, state *clientstate.Database) *integrationPublisherFixture {
	t.Helper()
	id, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish,
		Server: testPublisherServer, ServiceID: id, Target: "3000", Project: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Finish(context.Background(), nil) })
	return &integrationPublisherFixture{journal: journal, service: controlv1.Service{Id: id, Enabled: true,
		Protocol: controlv1.ServiceProtocolHTTP, Endpoint: &controlv1.ServiceEndpoint{Hostname: testPublisherHost, Port: 443, Public: true}}}
}

func (f *integrationPublisherFixture) snapshot() Snapshot {
	return Snapshot{Config: publisherservice.RunConfig{ServiceID: f.service.Id}, Service: f.service}
}

// the lifecycle tests substitute only service publication. prepared run facts
// are captured by the real owner and match this fixture's real local journal.
func (f *integrationPublisherFixture) ready(ctx context.Context, config publisherservice.RunConfig) (controlv1.ServiceRunPreparation, error) {
	id, err := opaqueid.New(opaqueid.ServiceRunPrefix)
	if err != nil {
		return controlv1.ServiceRunPreparation{}, err
	}
	prepared := controlv1.ServiceRunPreparation{ServiceId: f.service.Id, ServiceRunId: id,
		Hostname: f.service.Endpoint.Hostname, RunNumber: f.runs.Add(1)}
	if err := config.Prepared(prepared); err != nil {
		return prepared, err
	}
	if err := f.journal.SetProvisioning(ctx, uint64(prepared.RunNumber)); err != nil {
		return prepared, err
	}
	if err := f.journal.SetReady(ctx, "https://"+prepared.Hostname, uint64(prepared.RunNumber)); err != nil {
		return prepared, err
	}
	return prepared, config.Ready()
}

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
	fixture := newIntegrationPublisherFixture(t, state)
	store, err := state.Server(t.Context(), testPublisherServer)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{}, 1)
	draining := make(chan struct{}, 1)
	release := make(chan struct{})
	worker := Publisher{State: state, Store: store, Server: testPublisherServer, Hostname: testPublisherHost, interval: time.Millisecond,
		Prepare: func(context.Context) (Snapshot, error) {
			return fixture.snapshot(), nil
		},
		run: func(ctx context.Context, config publisherservice.RunConfig) error {
			if _, err := fixture.ready(ctx, config); err != nil {
				return err
			}
			started <- struct{}{}
			<-ctx.Done()
			config.ObserveReadiness(publisherservice.RunStatus{Ready: false})
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
	fixture := newIntegrationPublisherFixture(t, state)
	store, err := state.Server(t.Context(), testPublisherServer)
	if err != nil {
		t.Fatal(err)
	}
	checked := make(chan bool, 1)
	ctx, cancel := context.WithCancel(t.Context())
	worker := Publisher{State: state, Store: store, Server: testPublisherServer, Hostname: testPublisherHost, interval: time.Millisecond,
		Prepare: func(context.Context) (Snapshot, error) {
			return fixture.snapshot(), nil
		},
		run: func(ctx context.Context, config publisherservice.RunConfig) error {
			if _, err := fixture.ready(ctx, config); err != nil {
				return err
			}
			config.ObserveReadiness(publisherservice.RunStatus{Ready: false, ConfigurationCurrent: false})
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
	fixture := newIntegrationPublisherFixture(t, state)
	store, err := state.Server(t.Context(), testPublisherServer)
	if err != nil {
		t.Fatal(err)
	}
	var runs atomic.Int32
	second := make(chan bool, 1)
	ctx, cancel := context.WithCancel(t.Context())
	worker := Publisher{State: state, Store: store, Server: testPublisherServer, Hostname: testPublisherHost, interval: time.Millisecond,
		Prepare: func(context.Context) (Snapshot, error) {
			return fixture.snapshot(), nil
		},
		run: func(ctx context.Context, config publisherservice.RunConfig) error {
			if runs.Add(1) == 1 {
				if _, err := fixture.ready(ctx, config); err != nil {
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
	fixture := newIntegrationPublisherFixture(t, state)
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
			snapshot := fixture.snapshot()
			snapshot.Revision = fmt.Sprint(revision.Load())
			return snapshot, nil
		},
		Revision: func(context.Context) (string, error) { return fmt.Sprint(revision.Load()), nil },
		run: func(ctx context.Context, config publisherservice.RunConfig) error {
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

func TestIntegrationURLPublisherReadinessLossAndRecoveryUseTheSameOwner(t *testing.T) {
	state := integrationURLState(t)
	fixture := newIntegrationPublisherFixture(t, state)
	store, err := state.Server(t.Context(), testPublisherServer)
	if err != nil {
		t.Fatal(err)
	}
	var changes []bool
	checked := make(chan error, 1)
	ctx, cancel := context.WithCancel(t.Context())
	worker := Publisher{State: state, Store: store, Server: testPublisherServer, Hostname: testPublisherHost,
		Prepare: func(context.Context) (Snapshot, error) {
			snapshot := fixture.snapshot()
			snapshot.Readiness = func(_ context.Context, ready bool) error {
				changes = append(changes, ready)
				return nil
			}
			return snapshot, nil
		},
		run: func(ctx context.Context, config publisherservice.RunConfig) error {
			// status before the first Ready callback is not a ready publication.
			config.ObserveReadiness(publisherservice.RunStatus{Ready: true})
			ready, err := state.IntegrationURLReady(ctx, testPublisherServer, testPublisherHost)
			if err != nil || ready {
				checked <- errors.New("status announced readiness before Ready")
				return nil
			}
			if _, err := fixture.ready(ctx, config); err != nil {
				checked <- err
				return nil
			}
			for _, available := range []bool{false, true} {
				config.ObserveReadiness(publisherservice.RunStatus{Ready: available})
				ready, err := state.IntegrationURLReady(ctx, testPublisherServer, testPublisherHost)
				if err != nil || ready != available {
					checked <- errors.New("readiness did not follow the current run status")
					return nil
				}
			}
			checked <- nil
			<-ctx.Done()
			return nil
		}}
	result, done := make(chan error, 1), make(chan struct{})
	go func() { defer close(done); result <- worker.serve(ctx, time.Hour) }()
	t.Cleanup(func() { cancel(); waitIntegrationURLPublisher(t, done) })
	if err := waitIntegrationURLPublisher(t, checked); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := waitIntegrationURLPublisher(t, result); err != nil {
		t.Fatal(err)
	}
	waitIntegrationURLPublisher(t, done)
	// the same snapshot owns recovery and shutdown, without another preparation.
	if len(changes) < 5 || changes[0] || !changes[1] || changes[2] || !changes[3] || changes[len(changes)-1] {
		t.Fatal("local readiness records did not follow loss, recovery, and joined stop", changes)
	}
}

func TestIntegrationURLPublisherKeepsIndependentRunAndReadinessCleanupFailures(t *testing.T) {
	state := integrationURLState(t)
	fixture := newIntegrationPublisherFixture(t, state)
	store, err := state.Server(t.Context(), testPublisherServer)
	if err != nil {
		t.Fatal(err)
	}
	runProblem, cleanupProblem := errors.New("run cleanup failed"), errors.New("readiness cleanup failed")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	started := make(chan struct{})
	worker := Publisher{State: state, Store: store, Server: testPublisherServer, Hostname: testPublisherHost,
		Prepare: func(context.Context) (Snapshot, error) {
			snapshot := fixture.snapshot()
			marked := false
			snapshot.Readiness = func(_ context.Context, ready bool) error {
				if ready {
					marked = true
				} else if marked {
					return cleanupProblem
				}
				return nil
			}
			return snapshot, nil
		},
		run: func(ctx context.Context, config publisherservice.RunConfig) error {
			if _, err := fixture.ready(ctx, config); err != nil {
				return err
			}
			close(started)
			<-ctx.Done()
			return errors.Join(context.Canceled, runProblem)
		}}
	result, done := make(chan error, 1), make(chan struct{})
	go func() { defer close(done); result <- worker.serve(ctx, time.Hour) }()
	t.Cleanup(func() { cancel(); waitIntegrationURLPublisher(t, done) })
	waitIntegrationURLPublisher(t, started)
	cancel()
	err = waitIntegrationURLPublisher(t, result)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, runProblem) || !errors.Is(err, cleanupProblem) {
		t.Fatal("joined shutdown suppressed an independent failure", err)
	}
}

func TestIntegrationURLPublisherRequiresOneActualPreparedRun(t *testing.T) {
	state := integrationURLState(t)
	fixture := newIntegrationPublisherFixture(t, state)
	store, err := state.Server(t.Context(), testPublisherServer)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	checked := make(chan error, 1)
	worker := Publisher{State: state, Store: store, Server: testPublisherServer, Hostname: testPublisherHost,
		Prepare: func(context.Context) (Snapshot, error) { return fixture.snapshot(), nil },
		run: func(ctx context.Context, config publisherservice.RunConfig) error {
			if err := config.Ready(); !errors.Is(err, errIntegrationRunStale) {
				checked <- errors.New("Ready accepted an unprepared run")
				return nil
			}
			config.ObserveReadiness(publisherservice.RunStatus{Ready: true})
			if ready, err := state.IntegrationURLReady(ctx, testPublisherServer, testPublisherHost); err != nil || ready {
				checked <- errors.New("unprepared status created a readiness lease")
				return nil
			}
			prepared, err := fixture.ready(ctx, config)
			if err != nil {
				checked <- err
				return nil
			}
			// replacement must use a fresh serving operation with its own
			// callbacks, not retarget this operation's argument-free callbacks.
			prepared.RunNumber++
			if err := config.Prepared(prepared); !errors.Is(err, errIntegrationRunStale) {
				checked <- errors.New("Prepared replaced a captured service run")
				return nil
			}
			if ready, err := state.IntegrationURLReady(ctx, testPublisherServer, testPublisherHost); err != nil || !ready {
				checked <- errors.New("rejected replacement disturbed the current readiness lease")
				return nil
			}
			checked <- nil
			<-ctx.Done()
			return nil
		}}
	result, done := make(chan error, 1), make(chan struct{})
	go func() { defer close(done); result <- worker.serve(ctx, time.Hour) }()
	t.Cleanup(func() { cancel(); waitIntegrationURLPublisher(t, done) })
	if err := waitIntegrationURLPublisher(t, checked); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := waitIntegrationURLPublisher(t, result); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationURLPublisherLateCallbacksCannotTouchTheReplacement(t *testing.T) {
	state := integrationURLState(t)
	fixture := newIntegrationPublisherFixture(t, state)
	store, err := state.Server(t.Context(), testPublisherServer)
	if err != nil {
		t.Fatal(err)
	}
	type captured struct {
		config   publisherservice.RunConfig
		prepared controlv1.ServiceRunPreparation
	}
	started := make(chan captured, 2)
	var attempts, readyCalls, statusCalls atomic.Int32
	ctx, cancel := context.WithCancel(t.Context())
	worker := Publisher{State: state, Store: store, Server: testPublisherServer, Hostname: testPublisherHost, interval: time.Millisecond,
		Prepare: func(context.Context) (Snapshot, error) {
			snapshot := fixture.snapshot()
			snapshot.Config.Ready = func() error { readyCalls.Add(1); return nil }
			snapshot.Config.ObserveReadiness = func(publisherservice.RunStatus) { statusCalls.Add(1) }
			return snapshot, nil
		},
		run: func(ctx context.Context, config publisherservice.RunConfig) error {
			prepared, err := fixture.ready(ctx, config)
			if err != nil {
				return err
			}
			started <- captured{config, prepared}
			if attempts.Add(1) == 1 {
				return errors.New("restart the service run")
			}
			<-ctx.Done()
			return nil
		}}
	done := make(chan struct{})
	go func() { defer close(done); worker.Maintain(ctx) }()
	t.Cleanup(func() { cancel(); waitIntegrationURLPublisher(t, done) })
	old, current := waitIntegrationURLPublisher(t, started), waitIntegrationURLPublisher(t, started)
	if old.prepared.ServiceId != current.prepared.ServiceId || current.prepared.RunNumber <= old.prepared.RunNumber {
		t.Fatal("retry changed the saved service or reused a retired run", old.prepared, current.prepared)
	}
	if err := old.config.Ready(); !errors.Is(err, errIntegrationRunStale) {
		t.Fatal("retired Ready callback regained ownership", err)
	}
	if err := old.config.Prepared(old.prepared); !errors.Is(err, errIntegrationRunStale) {
		t.Fatal("retired preparation callback regained ownership", err)
	}
	old.config.ObserveReadiness(publisherservice.RunStatus{Ready: false})
	old.config.ObserveReadiness(publisherservice.RunStatus{Ready: true})
	if readyCalls.Load() != 2 || statusCalls.Load() != 0 {
		t.Fatal("retired callbacks reached the replacement's hooks", readyCalls.Load(), statusCalls.Load())
	}
	if ready, err := state.IntegrationURLReady(t.Context(), testPublisherServer, testPublisherHost); err != nil || !ready {
		t.Fatal("retired callbacks disturbed the current readiness lease", ready, err)
	}
}
