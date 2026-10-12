package clientruntime

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestListenerOwnershipPublicationAndReplacementRejectsStaleRuns(t *testing.T) {
	var runs atomic.Uint64
	started := make(chan uint64, 4)
	manager, err := New(t.Context(), t.TempDir(), t.TempDir(), []Service{{Name: "web", Directory: "."}, {Name: "api", Directory: "api"}}, func(ctx context.Context, service Service, observe func(uint64, bool) error) error {
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
	if !manager.Observe(Observation{RegistrationID: id, PublishRunNumber: run, Ready: true}) {
		t.Fatal("current observation rejected")
	}
	if err := manager.Register(id, "owner", "http://127.0.0.1:1235", "node"); err != nil {
		t.Fatal(err)
	}
	next := <-started
	if next == run || manager.Observe(Observation{RegistrationID: id, PublishRunNumber: run, Ready: true}) {
		t.Fatal("old run observation crossed listener replacement")
	}
	if !manager.Current("web", id, "http://127.0.0.1:1235", next) || manager.Current("web", id, "http://127.0.0.1:1234", run) {
		t.Fatal("request admission crossed replacement")
	}
	if err := manager.Unregister(id, "owner"); err != nil {
		t.Fatal(err)
	}
	if manager.Current("web", id, "http://127.0.0.1:1235", next) || manager.Observe(Observation{RegistrationID: id, PublishRunNumber: next, Ready: true}) {
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

func TestNamedPublicationSharesTheProjectLeaseAndFencesReplacedTargets(t *testing.T) {
	var runs atomic.Uint64
	started := make(chan Service, 2)
	manager, err := New(t.Context(), t.TempDir(), t.TempDir(), []Service{
		{Name: "web", Directory: "."}, {Name: "orders", Directory: ".", ServiceProtocol: "postgres"},
	}, func(ctx context.Context, service Service, observe func(uint64, bool) error) error {
		if err := observe(runs.Add(1), true); err != nil {
			return err
		}
		started <- service
		<-ctx.Done()
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	id, err := manager.Reserve("orders", "cli-owner", os.Getpid(), "orders.example:15432")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Register(id, "cli-owner", "http://127.0.0.1:5432", "node"); err == nil {
		t.Fatal("app registration claimed the named TCP service")
	}
	for _, target := range []string{"http://127.0.0.1:5432", "5432", "db:0"} {
		if err := manager.RegisterNamed(id, "cli-owner", target); err == nil {
			t.Fatalf("accepted noncanonical private TCP target %q", target)
		}
	}
	if manager.Snapshot().Services[0].Registered {
		t.Fatal("invalid target claimed a named publication")
	}
	if err := manager.RegisterNamed(id, "cli-owner", "127.0.0.1:5432"); err != nil {
		t.Fatal(err)
	}
	first := <-started
	if first.Framework != "" || first.ServiceProtocol != "postgres" || !manager.Current("orders", id, first.Target, 1) {
		t.Fatalf("named publication = %+v", first)
	}
	if _, err := manager.Reserve("orders", "other", os.Getpid(), "orders.example:15432"); !errors.Is(err, ErrOwnerConflict) {
		t.Fatalf("second owner claimed active publication: %v", err)
	}
	if err := manager.RegisterNamed(id, "cli-owner", "127.0.0.1:5433"); err != nil {
		t.Fatal(err)
	}
	second := <-started
	if second.Target != "127.0.0.1:5433" || manager.Current("orders", id, first.Target, 1) || !manager.Current("orders", id, second.Target, 2) {
		t.Fatalf("target replacement did not fence the first run: %+v", second)
	}
	appID, err := manager.Reserve("web", "app-owner", os.Getpid(), "https://web.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Register(appID, "app-owner", "http://127.0.0.1:3000", "node"); err != nil {
		t.Fatal(err)
	}
	app := <-started
	if app.Name != "web" || !manager.Current("web", appID, app.Target, 3) {
		t.Fatalf("app registration did not share the manager with a named publication: %+v", app)
	}
	if err := manager.Unregister(id, "cli-owner"); err != nil || manager.Current("orders", id, second.Target, 2) {
		t.Fatalf("stopping named publication = %v", err)
	}
	if !manager.Current("web", appID, app.Target, 3) {
		t.Fatal("stopping a named publication stopped the app")
	}
}

func TestNamedHTTPPublicationRequiresABoundOrigin(t *testing.T) {
	manager, err := New(t.Context(), t.TempDir(), t.TempDir(), []Service{{Name: "api", ServiceProtocol: "http"}},
		func(ctx context.Context, _ Service, _ func(uint64, bool) error) error { <-ctx.Done(); return ctx.Err() })
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	id, err := manager.Reserve("api", "cli-owner", os.Getpid(), "https://api.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.RegisterNamed(id, "cli-owner", "127.0.0.1:3000"); err == nil {
		t.Fatal("accepted a TCP address for an HTTP publication")
	}
	if err := manager.Register(id, "cli-owner", "http://127.0.0.1:3000", "node"); err == nil {
		t.Fatal("app registration claimed a named HTTP service")
	}
	if err := manager.RegisterNamed(id, "cli-owner", "http://127.0.0.1:3000"); err != nil {
		t.Fatal(err)
	}
	if got := manager.Snapshot().Services[0]; !got.Registered || got.Framework != "" || got.ServiceProtocol != "http" {
		t.Fatalf("named HTTP registration = %+v", got)
	}
}

func TestRegistrationAckDoesNotWaitForProvisioning(t *testing.T) {
	blocked := make(chan struct{})
	manager, err := New(t.Context(), t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, func(ctx context.Context, _ Service, _ func(uint64, bool) error) error {
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

func TestPublisherWarningsStayWithRunAndClearWhenRoutable(t *testing.T) {
	started := make(chan struct{})
	manager, err := New(t.Context(), t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, func(ctx context.Context, _ Service, _ func(uint64, bool) error) error {
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
	manager, err := New(t.Context(), project, state, []Service{{Name: "web"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cursor := manager.Snapshot().Cursor
	if _, err := manager.Reserve("web", "owner", 1, "https://web.example"); err != nil {
		t.Fatal(err)
	}
	manager.Close()
	restarted, err := New(t.Context(), project, state, []Service{{Name: "web"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	snapshot, err := ReadSnapshot(project, state)
	if err != nil {
		t.Fatal(err)
	}
	events, err := EventsAfter(snapshot, cursor)
	if err != nil || len(events) != 5 || snapshot.Services[0].Registered {
		t.Fatalf("resume = %#v, %v", events, err)
	}
	previous, _ := ParseCursor(cursor)
	for _, event := range events {
		value, _ := ParseCursor(event.Cursor)
		if value != previous+1 {
			t.Fatal("unordered journal")
		}
		previous = value
	}
	snapshot.Events = snapshot.Events[len(snapshot.Events)-1:]
	if _, err := EventsAfter(snapshot, "0"); !errors.Is(err, ErrCursorExpired) {
		t.Fatalf("expired cursor = %v", err)
	}
	if _, err := EventsAfter(snapshot, "99999"); !errors.Is(err, ErrCursorExpired) {
		t.Fatalf("future cursor = %v", err)
	}
}

func TestConfigurationReconciliationPreservesLiveAppsAndJoinsRemovedPublishers(t *testing.T) {
	started, stopped := make(chan struct{}), make(chan struct{})
	manager, err := New(t.Context(), t.TempDir(), t.TempDir(), []Service{{Name: "api", Readiness: Readiness{Path: "/"}}}, func(ctx context.Context, _ Service, observe func(uint64, bool) error) error {
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
	manager.Observe(Observation{RegistrationID: id, PublishRunNumber: 1, Ready: true, Readiness: Readiness{Path: "/"}})
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
	if manager.Current("api", id, "http://127.0.0.1:1234", 1) {
		t.Fatal("removed service still admitted requests")
	}
}

func TestPreparationKeepsTheManagerAliveUntilCleanupGrace(t *testing.T) {
	manager, err := New(t.Context(), t.TempDir(), t.TempDir(), []Service{{Name: "api"}}, nil)
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
