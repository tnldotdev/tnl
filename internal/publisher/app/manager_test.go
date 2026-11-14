package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
)

func TestWorkerCancellationRetainsIndependentFailures(t *testing.T) {
	operation, cleanup := errors.New("publication failed"), errors.New("deletion failed")
	err := independentWorkerFailure(errors.Join(context.Canceled, ErrRegistrationStale, operation, cleanup), true)
	if !errors.Is(err, operation) || !errors.Is(err, cleanup) || errors.Is(err, context.Canceled) || errors.Is(err, ErrRegistrationStale) {
		t.Fatal("cancellation erased an independent failure or retained an expected fence", err)
	}
	if err := independentWorkerFailure(ErrRegistrationStale, false); !errors.Is(err, ErrRegistrationStale) {
		t.Fatal("live worker failure was discarded", err)
	}
	wrapped := fmt.Errorf("worker: %w", errors.Join(context.Canceled, ErrRegistrationStale, operation, cleanup))
	err = independentWorkerFailure(wrapped, true)
	if !errors.Is(err, operation) || !errors.Is(err, cleanup) || errors.Is(err, context.Canceled) || errors.Is(err, ErrRegistrationStale) {
		t.Fatal("wrapped cancellation concealed a reportable independent failure", err)
	}
}

func TestUnregisterJoinsWorkerBeforeRetryableExactCleanup(t *testing.T) {
	operation, cleanup := errors.New("worker failed"), errors.New("cleanup failed")
	canceled, release, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
	manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, func(ctx context.Context, _ Service, _ func(PublicationUpdate) error) error {
		defer close(joined)
		<-ctx.Done()
		close(canceled)
		<-release
		return errors.Join(ctx.Err(), operation)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	var attempts atomic.Int32
	manager.Cleanup = func(Service) error {
		select {
		case <-joined:
		default:
			t.Error("cleanup ran before the worker joined")
		}
		if attempts.Add(1) == 1 {
			return cleanup
		}
		return nil
	}
	id, err := manager.Reserve("web", "owner", 1, "https://web.example")
	if err != nil {
		t.Fatal(err)
	}
	const target = "http://127.0.0.1:3000"
	if err := manager.Register(id, "owner", target, "node"); err != nil {
		t.Fatal(err)
	}
	unregistered := make(chan error, 1)
	go func() { unregistered <- manager.UnregisterTarget(id, "owner", target) }()
	<-canceled
	if attempts.Load() != 0 {
		t.Error("cleanup crossed the worker join")
	}
	close(release)
	if err := <-unregistered; !errors.Is(err, operation) || !errors.Is(err, cleanup) || errors.Is(err, context.Canceled) {
		t.Fatal("unregister lost an independent failure", err)
	}
	if _, found := manager.ServiceForRegistration(id); !found {
		t.Fatal("failed cleanup lost its registration")
	}
	if err := manager.UnregisterTarget(id, "owner", "http://127.0.0.1:4000"); !errors.Is(err, ErrRegistrationStale) || attempts.Load() != 1 {
		t.Fatal("wrong target retried retained cleanup", err)
	}
	if err := manager.UnregisterTarget(id, "owner", target); err != nil || attempts.Load() != 2 {
		t.Fatal("exact cleanup could not retry", err)
	}
	if _, found := manager.ServiceForRegistration(id); found {
		t.Fatal("successful cleanup retained its registration")
	}
}

func TestPermanentCleanupRetiresJoinedRegistrationAndPreservesFailures(t *testing.T) {
	for _, stopped := range []string{"close", "expired", "dead"} {
		t.Run(stopped, func(t *testing.T) {
			operation, cleanup := errors.New("worker failed independently"), errors.New("deletion authority was revoked")
			canceled, release, joined := make(chan struct{}), make(chan struct{}), make(chan struct{})
			manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, func(ctx context.Context, _ Service, _ func(PublicationUpdate) error) error {
				defer close(joined)
				<-ctx.Done()
				close(canceled)
				<-release
				return errors.Join(ctx.Err(), operation)
			})
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			var attempts atomic.Int32
			manager.Cleanup = func(Service) error {
				select {
				case <-joined:
				default:
					t.Error("cleanup crossed the worker join")
				}
				attempts.Add(1)
				return errors.Join(ErrCleanupPermanent, cleanup)
			}
			id, err := manager.Reserve("web", "owner", 1, "https://web.example")
			if err != nil {
				t.Fatal(err)
			}
			const target = "http://127.0.0.1:3000"
			if err := manager.Register(id, "owner", target, "node"); err != nil {
				t.Fatal(err)
			}
			stoppedResult := make(chan error, 1)
			if stopped == "expired" {
				manager.mu.Lock()
				manager.registrations["web"].expires = time.Now().Add(-time.Second)
				manager.mu.Unlock()
			}
			go func() {
				if stopped == "close" {
					stoppedResult <- manager.UnregisterTarget(id, "owner", target)
				} else {
					manager.Sweep(func(int) bool { return stopped != "dead" })
					stoppedResult <- manager.RetirementError()
				}
			}()
			<-canceled
			if attempts.Load() != 0 {
				t.Fatal("cleanup ran before the worker joined")
			}
			close(release)
			result := <-stoppedResult
			if !errors.Is(result, operation) || !errors.Is(result, cleanup) ||
				stopped == "close" && !errors.Is(result, ErrRegistrationStopped) {
				t.Fatal("local retirement lost its failure", result)
			}
			if _, found := manager.ServiceForRegistration(id); found {
				t.Fatal("permanent cleanup retained a dead registration")
			}
			if failure := manager.Snapshot().Services[0].Failure; failure != "runtime.publication_cleanup_failed" {
				t.Fatal("journal did not report failed remote cleanup", failure)
			}
			if err := manager.RetirementError(); !errors.Is(err, operation) || !errors.Is(err, cleanup) {
				t.Fatal("owner retirement lost an independent failure", err)
			}
			manager.mu.Lock()
			manager.idleSince = manager.idleSince.Add(-CleanupGrace)
			manager.mu.Unlock()
			if !manager.Sweep(func(int) bool { return false }) || attempts.Load() != 1 {
				t.Fatal("idle owner retried permanent deletion or could not exit", attempts.Load())
			}
		})
	}
}

func TestFinalCloseReportsRetryableCleanupFailure(t *testing.T) {
	cleanup := errors.New("temporary deletion failure")
	manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	manager.Cleanup = func(Service) error { return cleanup }
	if _, err := manager.Reserve("web", "owner", 1, ""); err != nil {
		t.Fatal(err)
	}
	manager.Close()
	if !errors.Is(manager.RetirementError(), cleanup) {
		t.Fatal("final owner shutdown swallowed cleanup failure", manager.RetirementError())
	}
}

func TestStoppedOutcomeReplayIsExactBoundedAndDoesNotDelayIdleExit(t *testing.T) {
	manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	cleanup := errors.New("deletion permanently denied")
	var attempts int
	manager.Cleanup = func(Service) error {
		attempts++
		return errors.Join(ErrCleanupPermanent, cleanup)
	}
	id, err := manager.Reserve("web", "owner", 1, "https://web.example")
	if err != nil {
		t.Fatal(err)
	}
	first := manager.UnregisterTarget(id, "owner", "")
	if !errors.Is(first, ErrRegistrationStopped) || !errors.Is(first, cleanup) {
		t.Fatal("missing terminal cleanup outcome", first)
	}
	if replay := manager.UnregisterTarget(id, "owner", ""); replay != first || attempts != 1 {
		t.Fatal("lost reply changed the terminal outcome or retried deletion", replay, attempts)
	}
	for _, wrong := range []struct{ id, owner, target string }{
		{id, "other", ""}, {id, "owner", "http://127.0.0.1:3000"}, {"other", "owner", ""},
	} {
		if err := manager.UnregisterTarget(wrong.id, wrong.owner, wrong.target); !errors.Is(err, ErrRegistrationStale) {
			t.Fatal("another binding replayed a stopped outcome", err)
		}
	}
	manager.mu.Lock()
	manager.idleSince = manager.idleSince.Add(-CleanupGrace)
	manager.mu.Unlock()
	if !manager.Sweep(nil) {
		t.Fatal("outcome replay extended owner lifetime")
	}
	manager.mu.Lock()
	outcome := manager.stopped[id]
	outcome.expires = time.Now().Add(-time.Second)
	manager.stopped[id] = outcome
	manager.mu.Unlock()
	if err := manager.UnregisterTarget(id, "owner", ""); !errors.Is(err, ErrRegistrationStale) {
		t.Fatal("expired terminal outcome was retained", err)
	}
	for index := range maxStoppedOutcomes + 1 {
		if _, err := manager.Reserve("web", "owner", 1, ""); err != nil {
			t.Fatal(err)
		}
		// populate distinct stopped service names to prove the capacity bound.
		manager.mu.Lock()
		service := *manager.serviceLocked("web")
		service.Name = fmt.Sprintf("service-%d", index)
		manager.rememberStoppedLocked(service, "owner", service.Target, first)
		manager.serviceLocked("web").releaseRegistration()
		delete(manager.registrations, "web")
		manager.mu.Unlock()
	}
	if len(manager.stopped) != maxStoppedOutcomes {
		t.Fatal("stopped outcomes exceeded their capacity", len(manager.stopped))
	}
	manager.mu.Lock()
	manager.stopped[id] = stoppedOutcome{service: "web", owner: "owner", expires: time.Now().Add(time.Minute), err: first}
	manager.mu.Unlock()
	if _, err := manager.Reserve("web", "replacement", 2, ""); err != nil {
		t.Fatal(err)
	}
	if err := manager.UnregisterTarget(id, "owner", ""); !errors.Is(err, ErrRegistrationStale) {
		t.Fatal("a replacement binding retained the old stopped outcome", err)
	}
}

func TestSuccessfulUnregisterReplyCanBeReplayedWithoutRepeatingCleanup(t *testing.T) {
	manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	attempts := 0
	manager.Cleanup = func(Service) error {
		attempts++
		return nil
	}
	id, err := manager.Reserve("web", "owner", 1, "")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := manager.UnregisterTarget(id, "owner", ""); err != nil {
			t.Fatal("exact successful cleanup acknowledgment could not replay", err)
		}
	}
	if attempts != 1 {
		t.Fatal("successful cleanup repeated after losing its reply", attempts)
	}
	if err := manager.UnregisterTarget(id, "another-owner", ""); !errors.Is(err, ErrRegistrationStale) {
		t.Fatal("successful acknowledgment crossed its owner fence", err)
	}
}

func TestPreparedUnregisterRetainsAcceptedTargetWithoutBindingAListener(t *testing.T) {
	for _, permanent := range []bool{false, true} {
		t.Run(fmt.Sprint(permanent), func(t *testing.T) {
			manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			transient := errors.New("cleanup temporarily unavailable")
			attempts := 0
			manager.Cleanup = func(service Service) error {
				attempts++
				if service.Target != "" || service.Registered || service.RunNumber != 0 {
					t.Fatal("unregister invented a listener binding", service)
				}
				if attempts == 1 {
					return transient
				}
				if permanent {
					return errors.Join(ErrCleanupPermanent, errors.New("cleanup permanently failed"))
				}
				return nil
			}
			id, err := manager.Reserve("web", "owner", 1, "")
			if err != nil {
				t.Fatal(err)
			}
			const target = "http://127.0.0.1:3000"
			if err := manager.UnregisterTarget(id, "owner", target); !errors.Is(err, transient) {
				t.Fatal("preparation cleanup did not retain its transient failure", err)
			}
			if err := manager.UnregisterTarget(id, "owner", "http://127.0.0.1:4000"); !errors.Is(err, ErrRegistrationStale) || attempts != 1 {
				t.Fatal("a different target retried cleanup of an unbound preparation", err)
			}
			first := manager.UnregisterTarget(id, "owner", target)
			if permanent != errors.Is(first, ErrRegistrationStopped) {
				t.Fatal("wrong completed cleanup outcome", first)
			}
			if replay := manager.UnregisterTarget(id, "owner", target); replay != first || attempts != 2 {
				t.Fatal("exact prepared-only replay lost its accepted target", replay, attempts)
			}
			for _, retry := range []struct{ id, owner, target string }{
				{id, "owner", ""},
				{id, "another-owner", target},
				{"reg_00000000000000000000000000000000", "owner", target},
			} {
				if err := manager.UnregisterTarget(retry.id, retry.owner, retry.target); !errors.Is(err, ErrRegistrationStale) || attempts != 2 {
					t.Fatal("prepared-only replay crossed its accepted binding", err, attempts)
				}
			}
			if service := manager.Snapshot().Services[0]; service.Target != "" || service.Registered {
				t.Fatal("cleanup outcome became publication metadata", service)
			}
		})
	}
}

func newTestManager(t *testing.T, project, root string, services []Service, run Run) (*Manager, error) {
	t.Helper()
	project, err := filepath.EvalSymlinks(project)
	if err != nil {
		return nil, err
	}
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(root, "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = database.Close() })
	return New(t.Context(), project, database, services, run)
}

func TestListenerOwnershipPublicationAndReplacementRejectsStaleRuns(t *testing.T) {
	var runs atomic.Uint64
	started := make(chan uint64, 4)
	manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web", Directory: "."}, {Name: "api", Directory: "api"}}, func(ctx context.Context, service Service, observe func(PublicationUpdate) error) error {
		run := runs.Add(1)
		if err := observe(PublicationUpdate{RunNumber: run, Routable: true, Target: service.Target, TunnelID: service.TunnelID, PublicURL: service.PublicURL}); err != nil {
			return err
		}
		started <- run
		<-ctx.Done()
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	id, err := manager.Reserve("web", "owner", 1, "https://web.example")
	if err != nil {
		t.Fatal(err)
	}
	if manager.Snapshot().Services[1].Registered {
		t.Fatal("preparation claimed a listener")
	}
	if _, err := manager.Reserve("web", "other", 2, "https://web.example"); !errors.Is(err, ErrOwnerConflict) {
		t.Fatalf("duplicate owner = %v", err)
	}
	if err := manager.Register(id, "owner", "http://127.0.0.1:1234", "node"); err != nil {
		t.Fatal(err)
	}
	run := <-started
	if !manager.Observe(Observation{Target: "http://127.0.0.1:1234", RegistrationID: id, RunNumber: run, Ready: true}) {
		t.Fatal("current observation rejected")
	}
	if err := manager.Register(id, "owner", "http://127.0.0.1:1235", "node"); err != nil {
		t.Fatal(err)
	}
	next := <-started
	if next == run || manager.Observe(Observation{Target: "http://127.0.0.1:1234", RegistrationID: id, RunNumber: run, Ready: true}) {
		t.Fatal("old run observation crossed listener replacement")
	}
	if !manager.CurrentRun("web", id, "http://127.0.0.1:1235", next) || manager.CurrentRun("web", id, "http://127.0.0.1:1234", run) {
		t.Fatal("request admission crossed replacement")
	}
	if err := manager.RenewTarget(id, "owner", "http://127.0.0.1:1234"); !errors.Is(err, ErrRegistrationStale) {
		t.Fatalf("old target renewed replacement: %v", err)
	}
	if err := manager.UnregisterTarget(id, "owner", "http://127.0.0.1:1234"); !errors.Is(err, ErrRegistrationStale) {
		t.Fatalf("old target stopped replacement: %v", err)
	}
	if err := manager.Unregister(id, "owner"); err != nil {
		t.Fatal(err)
	}
	if manager.CurrentRun("web", id, "http://127.0.0.1:1235", next) || manager.Observe(Observation{Target: "http://127.0.0.1:1235", RegistrationID: id, RunNumber: next, Ready: true}) {
		t.Fatal("unregistered listener admitted work")
	}
	restarted, err := manager.Reserve("web", "new", 2, "https://web.example")
	if err != nil || restarted == id {
		t.Fatalf("restart ownership = %s, %v", restarted, err)
	}
	if err := manager.Renew(id, "owner"); !errors.Is(err, ErrRegistrationStale) {
		t.Fatalf("old renewal = %v", err)
	}
	manager.mu.Lock()
	manager.registrations["web"].expires = time.Now().Add(-time.Second)
	manager.mu.Unlock()
	manager.Sweep(func(int) bool { return true })
	if err := manager.Renew(restarted, "new"); !errors.Is(err, ErrRegistrationStale) {
		t.Fatalf("expired renewal = %v", err)
	}
	manager.mu.Lock()
	manager.idleSince = time.Now().Add(-CleanupGrace)
	manager.mu.Unlock()
	if !manager.Sweep(func(int) bool { return true }) {
		t.Fatal("manager did not exit after cleanup grace")
	}
}

func TestCurrentRegistrationAndExactRunKeepLivenessAndReadinessSeparate(t *testing.T) {
	manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, func(ctx context.Context, _ Service, _ func(PublicationUpdate) error) error {
		<-ctx.Done()
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	var alive atomic.Bool
	alive.Store(true)
	manager.Alive = func(int) bool { return alive.Load() }
	id, err := manager.Reserve("web", "owner", 1, "https://web.example")
	if err != nil {
		t.Fatal(err)
	}
	const target = "http://127.0.0.1:3000"
	if err := manager.Register(id, "owner", target, ""); err != nil {
		t.Fatal(err)
	}
	if !manager.CurrentRegistration("web", id, target) || manager.CurrentRun("web", id, target, 0) || manager.CurrentRun("web", id, target, 0) {
		t.Fatal("registration ownership granted run-zero authority")
	}
	if err := manager.Published(id, PublicationUpdate{Target: target, Routable: true}); !errors.Is(err, ErrRegistrationStale) {
		t.Fatal("run zero became routable", err)
	}
	if err := manager.Published(id, PublicationUpdate{RunNumber: 7, Target: target}); err != nil {
		t.Fatal(err)
	}
	service, current := manager.ServiceForRun("web", id, target, 7)
	if !current || !service.Registered || service.Routable || service.Ready || manager.CurrentRun("web", id, target, 8) {
		t.Fatal("exact provisioning run was conflated with routability", service)
	}
	observation := Observation{RegistrationID: id, Target: target, RunNumber: 7, Ready: true}
	if manager.Observe(observation) {
		t.Fatal("unroutable run accepted readiness")
	}
	if err := manager.Published(id, PublicationUpdate{RunNumber: 7, Routable: true, Target: target, PublicURL: service.PublicURL}); err != nil || !manager.Observe(observation) {
		t.Fatal("routable current run rejected readiness", err)
	}
	alive.Store(false)
	if manager.CurrentRegistration("web", id, target) || manager.CurrentRun("web", id, target, 7) || manager.Observe(observation) {
		t.Fatal("dead owner retained registration or run authority")
	}
}

func TestRegistrationAckDoesNotWaitForProvisioning(t *testing.T) {
	blocked := make(chan struct{})
	manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, func(ctx context.Context, _ Service, _ func(PublicationUpdate) error) error {
		close(blocked)
		<-ctx.Done()
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	id, err := manager.Reserve("web", "owner", 1, "https://web.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Register(id, "owner", "http://127.0.0.1:1234", "vite"); err != nil {
		t.Fatal(err)
	}
	<-blocked
	service := manager.Snapshot().Services[0]
	if !service.Registered || service.Routable || service.Ready {
		t.Fatalf("registration = %#v", service)
	}
}

func TestRegisteredListenerSurvivesPublicationFailureAndCanRetry(t *testing.T) {
	fail := make(chan struct{})
	retried := make(chan struct{})
	var attempts atomic.Uint64
	manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, func(ctx context.Context, service Service, observe func(PublicationUpdate) error) error {
		run := attempts.Add(1)
		if err := observe(PublicationUpdate{RunNumber: run, Routable: true, Target: service.Target, TunnelID: service.TunnelID, PublicURL: service.PublicURL}); err != nil {
			return err
		}
		if run != 1 {
			close(retried)
			<-ctx.Done()
			return ctx.Err()
		}
		select {
		case <-fail:
			return errors.New("publication failed")
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	id, err := manager.Reserve("web", "owner", 1, "https://web.example")
	if err != nil {
		t.Fatal(err)
	}
	const target = "http://127.0.0.1:3000"
	cursor := manager.Snapshot().Cursor
	if err := manager.Register(id, "owner", target, "node"); err != nil {
		t.Fatal(err)
	}
	manager.mu.Lock()
	done := manager.registrations["web"].done
	manager.mu.Unlock()
	close(fail)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("failed publication did not finish")
	}
	snapshot := manager.Snapshot()
	service := snapshot.Services[0]
	if !service.Registered || service.Routable || service.Ready || service.Observation != nil || service.ProvisioningStage != "" || service.Failure != "runtime.publication_failed" || !manager.CurrentRun("web", id, target, 1) {
		t.Fatal("publication failure released the listener or retained readiness", service)
	}
	events, err := EventsAfterFrom(t.Context(), manager.database, snapshot.Project, cursor)
	if err != nil || len(events) != 3 || events[2].Type != "service.failed" || events[2].Cursor != snapshot.Cursor || events[2].Service == nil || *events[2].Service != service {
		t.Fatal("failure snapshot and event cursor diverged", events, err)
	}
	if err := manager.RenewTarget(id, "owner", target); err != nil {
		t.Fatal("publication failure revoked listener renewal", err)
	}
	if err := manager.Register(id, "owner", target, "node"); err != nil {
		t.Fatal("same listener could not retry publication", err)
	}
	select {
	case <-retried:
	case <-time.After(5 * time.Second):
		t.Fatal("same listener did not restart publication")
	}
	service = manager.Snapshot().Services[0]
	if !service.Registered || !service.Routable || service.Ready || service.RegistrationID != id || service.RunNumber != 2 || service.Failure != "" {
		t.Fatal("publication retry lost the listener or retained its failure", service)
	}
}

func TestRegistrationInvalidationFencesCallbacksBeforeJoining(t *testing.T) {
	for _, action := range []string{"replace", "unregister"} {
		t.Run(action, func(t *testing.T) {
			started := make(chan struct{}, 2)
			canceled, release := make(chan struct{}), make(chan struct{})
			late := make(chan error, 1)
			var attempts atomic.Uint64
			manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, func(ctx context.Context, service Service, observe func(PublicationUpdate) error) error {
				run := attempts.Add(1)
				if err := observe(PublicationUpdate{RunNumber: run, Routable: true, Target: service.Target, TunnelID: service.TunnelID, PublicURL: service.PublicURL}); err != nil {
					return err
				}
				started <- struct{}{}
				<-ctx.Done()
				if run == 1 {
					late <- observe(PublicationUpdate{RunNumber: run + 1, Routable: true, Target: service.Target, TunnelID: service.TunnelID, PublicURL: service.PublicURL})
					close(canceled)
					<-release
				}
				return ctx.Err()
			})
			if err != nil {
				t.Fatal(err)
			}
			defer manager.Close()
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			id, err := manager.Reserve("web", "owner", 1, "https://web.example")
			if err != nil {
				t.Fatal(err)
			}
			const target = "http://127.0.0.1:3000"
			if err := manager.Register(id, "owner", target, "node"); err != nil {
				t.Fatal(err)
			}
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("publication did not start")
			}
			if err := manager.BindTunnel("web", id, target, "tunnel_current"); err != nil {
				t.Fatal(err)
			}
			probe := Observation{RegistrationID: id, Target: target, RunNumber: 1, Ready: true}
			if !manager.Observe(probe) {
				t.Fatal("current probe was rejected")
			}
			done := make(chan error, 1)
			go func() {
				if action == "replace" {
					done <- manager.Register(id, "owner", "http://127.0.0.1:3001", "node")
				} else {
					done <- manager.Unregister(id, "owner")
				}
			}()
			select {
			case <-canceled:
			case <-time.After(5 * time.Second):
				t.Fatal("invalidation did not cancel the worker")
			}
			if err := <-late; !errors.Is(err, ErrRegistrationStale) {
				t.Fatal("late publication callback crossed invalidation", err)
			}
			service := manager.Snapshot().Services[0]
			if service.Registered || service.Routable || service.Ready || service.Observation != nil || service.RegistrationID != id || service.Target != target || service.TunnelID != "tunnel_current" || service.RunNumber != 1 {
				t.Fatal("invalidation lost identity before the worker joined", service)
			}
			if manager.Observe(probe) || manager.CurrentRun("web", id, target, 1) {
				t.Fatal("invalidated registration accepted old work")
			}
			select {
			case err := <-done:
				t.Fatal("operation returned before the worker joined", err)
			default:
			}
			select {
			case <-started:
				t.Fatal("replacement started before the worker joined")
			default:
			}
			unblock()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("operation did not join the worker")
			}
			if action == "unregister" {
				service = manager.Snapshot().Services[0]
				if service.RegistrationID != "" || service.Target != "" || service.TunnelID != "" || service.RunNumber != 0 {
					t.Fatal("joined registration retained identity", service)
				}
			} else {
				select {
				case <-started:
				case <-time.After(5 * time.Second):
					t.Fatal("replacement did not start after the join")
				}
				service = manager.Snapshot().Services[0]
				if !service.Registered || !service.Routable || service.Ready || service.RunNumber != 2 || service.Target != "http://127.0.0.1:3001" || manager.Observe(probe) {
					t.Fatal("old readiness crossed the joined replacement", service)
				}
			}
		})
	}
}

func TestPublisherWarningsStayWithRunAndClearWhenRoutable(t *testing.T) {
	started := make(chan struct{})
	manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, func(ctx context.Context, _ Service, _ func(PublicationUpdate) error) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	id, err := manager.Reserve("web", "owner", 1, "https://web.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Register(id, "owner", "http://127.0.0.1:1234", "node"); err != nil {
		t.Fatal(err)
	}
	<-started
	if err := manager.Published(id, PublicationUpdate{RunNumber: 1, Target: "http://127.0.0.1:1234"}); err != nil {
		t.Fatal(err)
	}
	manager.SetProvisioningStage("web", id, 1, "publisher_connections")
	manager.SetProvisioningStage("web", "reg_outdated", 1, "certificate")
	if got := manager.Snapshot().Services[0].ProvisioningStage; got != "publisher_connections" {
		t.Fatalf("provisioning stage = %s", got)
	}
	manager.RecordWarning("web", id, "runtime.provisioning_stalled")
	first := manager.Snapshot()
	if first.Services[0].Failure != "runtime.provisioning_stalled" {
		t.Fatalf("warning was not recorded: %+v", first.Services[0])
	}
	manager.RecordWarning("web", id, "runtime.provisioning_stalled")
	manager.RecordWarning("web", "reg_outdated", "runtime.unrelated")
	if manager.Snapshot().Cursor != first.Cursor {
		t.Fatal("repeated or stale warning advanced the event cursor")
	}
	if err := manager.Published(id, PublicationUpdate{RunNumber: 1, Routable: true, Target: "http://127.0.0.1:1234", PublicURL: "https://web.example"}); err != nil {
		t.Fatal(err)
	}
	if got := manager.Snapshot().Services[0]; got.Failure != "" || !got.Routable || got.ProvisioningStage != "" {
		t.Fatalf("warning remained after publication became routable: %+v", got)
	}
}

func TestJournalResumeAndManagerRestartCursor(t *testing.T) {
	project, state := t.TempDir(), t.TempDir()
	manager, err := newTestManager(t, project, state, []Service{{Name: "web"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cursor := manager.Snapshot().Cursor
	if _, err := manager.Reserve("web", "owner", 1, "https://web.example"); err != nil {
		t.Fatal(err)
	}
	manager.Close()
	restarted, err := New(t.Context(), manager.snapshot.Project, manager.database, []Service{{Name: "web"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	snapshot, err := ReadSnapshotFrom(t.Context(), manager.database, manager.snapshot.Project)
	if err != nil {
		t.Fatal(err)
	}
	events, err := EventsAfterFrom(t.Context(), manager.database, snapshot.Project, cursor)
	if err != nil || len(events) != 5 || snapshot.Services[0].Registered {
		t.Fatalf("resume = %#v, %v", events, err)
	}
	previous := cursor
	for _, event := range events {
		if event.Cursor == previous || event.Cursor == "" {
			t.Fatal("unordered journal")
		}
		previous = event.Cursor
	}
	if _, err := EventsAfterFrom(t.Context(), manager.database, snapshot.Project, "0"); !errors.Is(err, ErrCursorExpired) {
		t.Fatalf("expired cursor = %v", err)
	}
	if _, err := EventsAfterFrom(t.Context(), manager.database, snapshot.Project, "99999"); !errors.Is(err, ErrCursorExpired) {
		t.Fatalf("future cursor = %v", err)
	}
}

func TestConfigurationReconciliationPreservesLiveAppsAndJoinsRemovedPublishers(t *testing.T) {
	started, stopped := make(chan struct{}), make(chan struct{})
	manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "api", Readiness: Readiness{Path: "/"}}}, func(ctx context.Context, service Service, observe func(PublicationUpdate) error) error {
		if err := observe(PublicationUpdate{RunNumber: 1, Routable: true, Target: service.Target, TunnelID: service.TunnelID, PublicURL: service.PublicURL}); err != nil {
			return err
		}
		close(started)
		<-ctx.Done()
		close(stopped)
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	id, err := manager.Reserve("api", "owner", 1, "https://api.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Register(id, "owner", "http://127.0.0.1:1234", "node"); err != nil {
		t.Fatal(err)
	}
	<-started
	if !manager.Observe(Observation{Target: "http://127.0.0.1:1234", RegistrationID: id, RunNumber: 1, Ready: true, Readiness: Readiness{Path: "/"}}) {
		t.Fatal("current readiness observation rejected")
	}
	if err := manager.Configure([]Service{{Name: "api", Readiness: Readiness{Path: "/health"}}, {Name: "worker"}}); err != nil {
		t.Fatal(err)
	}
	snapshot := manager.Snapshot()
	if len(snapshot.Services) != 2 || !snapshot.Services[0].Registered || !snapshot.Services[0].Routable || snapshot.Services[0].Ready || snapshot.Services[1].Registered {
		t.Fatalf("configuration = %#v", snapshot.Services)
	}
	if err := manager.Configure([]Service{{Name: "worker"}}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("configuration did not join the removed publisher")
	}
	if manager.CurrentRun("api", id, "http://127.0.0.1:1234", 1) {
		t.Fatal("removed service still admitted requests")
	}
}

func TestPreparationKeepsTheManagerAliveUntilCleanupGrace(t *testing.T) {
	manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "api"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	finish := manager.BeginPreparation()
	manager.mu.Lock()
	manager.idleSince = time.Now().Add(-2 * CleanupGrace)
	manager.mu.Unlock()
	if manager.Sweep(func(int) bool { return true }) {
		t.Fatal("manager exited while preparing metadata")
	}
	finish()
	if manager.Sweep(func(int) bool { return true }) {
		t.Fatal("manager skipped the cleanup grace after preparation")
	}
}

func TestAbruptOwnerRestartInvalidatesPersistedRegistration(t *testing.T) {
	manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web", ServiceProtocol: "http"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	manager.Close()
	crashed := manager.Snapshot()
	crashed.Services[0].Registered, crashed.Services[0].Routable, crashed.Services[0].Ready = true, true, true
	crashed.Services[0].RegistrationID = "reg_previous"
	crashed.Services[0].RunNumber = 7
	if err := CommitSnapshot(t.Context(), manager.database, &crashed, "service.registered", nil); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(t.Context(), crashed.Project, manager.database, []Service{{Name: "web", ServiceProtocol: "http"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	service := restarted.Snapshot().Services[0]
	if service.Registered || service.Routable || service.Ready || service.RegistrationID != "" || service.Failure != "runtime.manager_restarted" {
		t.Fatalf("restart retained old ownership: %+v", service)
	}
	events, err := EventsAfterFrom(t.Context(), manager.database, crashed.Project, crashed.Cursor)
	if err != nil || len(events) != 1 || events[0].Type != "runtime.restarted" {
		t.Fatalf("restart events=%+v err=%v", events, err)
	}
	if err := restarted.Renew("reg_previous", "owner"); !errors.Is(err, ErrRegistrationStale) {
		t.Fatal("previous registration renewed after process restart")
	}
}
