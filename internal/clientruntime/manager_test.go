package clientruntime

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestListenerOwnershipPublicationAndReplacementFences(t *testing.T) {
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

func TestPublisherWarningsStayFencedAndClearWhenRoutable(t *testing.T) {
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

func TestJournalResumeAndManagerRestartWatermark(t *testing.T) {
	project, state := t.TempDir(), t.TempDir()
	manager, err := New(t.Context(), project, state, []Service{{Name: "web"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	watermark := manager.Snapshot().Cursor
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
	events, err := EventsAfter(snapshot, watermark)
	if err != nil || len(events) != 5 || snapshot.Services[0].Registered {
		t.Fatalf("resume = %#v, %v", events, err)
	}
	previous, _ := ParseCursor(watermark)
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
