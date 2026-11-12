package app

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
)

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

func TestApplicationPublicationShutdownCancelsSiblingsBeforeJoining(t *testing.T) {
	started := make(chan struct{}, 2)
	allCanceled := make(chan struct{})
	force := make(chan struct{})
	var canceled atomic.Int32
	manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web"}, {Name: "api"}}, func(ctx context.Context, _ Service, _ func(uint64, bool) error) error {
		started <- struct{}{}
		<-ctx.Done()
		if canceled.Add(1) == 2 {
			close(allCanceled)
		}
		select {
		case <-allCanceled:
		case <-force:
		}
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"web", "api"} {
		id, err := manager.Reserve(name, "owner", 1, "https://"+name+".example")
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Register(id, "owner", "http://127.0.0.1:3000", ""); err != nil {
			t.Fatal(err)
		}
	}
	<-started
	<-started
	done := make(chan error, 1)
	go func() { done <- manager.CloseError() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		close(force)
		<-done
		t.Fatal("one publication's join delayed canceling its sibling")
	}
}

func TestListenerOwnershipPublicationAndReplacementRejectsStaleRuns(t *testing.T) {
	var runs atomic.Uint64
	started := make(chan uint64, 4)
	manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web", Directory: "."}, {Name: "api", Directory: "api"}}, func(ctx context.Context, service Service, observe func(uint64, bool) error) error {
		run := runs.Add(1)
		if err := observe(run, true); err != nil {
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
	manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, func(ctx context.Context, _ Service, _ func(uint64, bool) error) error {
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
	if err := manager.Published(id, 0, true); !errors.Is(err, ErrRegistrationStale) {
		t.Fatal("run zero became routable", err)
	}
	if err := manager.Published(id, 7, false); err != nil {
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
	if err := manager.Published(id, 7, true); err != nil || !manager.Observe(observation) {
		t.Fatal("routable current run rejected readiness", err)
	}
	alive.Store(false)
	if manager.CurrentRegistration("web", id, target) || manager.CurrentRun("web", id, target, 7) || manager.Observe(observation) {
		t.Fatal("dead owner retained registration or run authority")
	}
}

func TestRegistrationAckDoesNotWaitForProvisioning(t *testing.T) {
	blocked := make(chan struct{})
	manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, func(ctx context.Context, _ Service, _ func(uint64, bool) error) error {
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
	manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, func(ctx context.Context, _ Service, observe func(uint64, bool) error) error {
		run := attempts.Add(1)
		if err := observe(run, true); err != nil {
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
			manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, func(ctx context.Context, _ Service, observe func(uint64, bool) error) error {
				run := attempts.Add(1)
				if err := observe(run, true); err != nil {
					return err
				}
				started <- struct{}{}
				<-ctx.Done()
				if run == 1 {
					late <- observe(run+1, true)
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
	manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, func(ctx context.Context, _ Service, _ func(uint64, bool) error) error {
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
	if err := manager.Published(id, 1, false); err != nil {
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
	if err := manager.Published(id, 1, true); err != nil {
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
	manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "api", Readiness: Readiness{Path: "/"}}}, func(ctx context.Context, _ Service, observe func(uint64, bool) error) error {
		if err := observe(1, true); err != nil {
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
