package app

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestRegistrationCloseRetriesCleanupAndKeepsCanceledFailure(t *testing.T) {
	workerFailure := errors.New("worker cleanup failed independently")
	cleanupFailure := errors.New("allocation delete failed")
	started := make(chan struct{})
	manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, func(ctx context.Context, _ Service, _ func(uint64, bool) error) error {
		close(started)
		<-ctx.Done()
		return errors.Join(ctx.Err(), workerFailure)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	id, err := manager.Reserve("web", "owner", 1, "https://web.example")
	if err != nil {
		t.Fatal(err)
	}
	var attempts atomic.Int32
	if err := manager.SetCleanup(id, "owner", func() error {
		if attempts.Add(1) <= 2 {
			return cleanupFailure
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Register(id, "owner", "http://127.0.0.1:3000", ""); err != nil {
		t.Fatal(err)
	}
	<-started
	if err := manager.UnregisterTarget(id, "owner", "http://127.0.0.1:3000"); !errors.Is(err, cleanupFailure) {
		t.Fatal("first close lost retryable cleanup failure", err)
	}
	if service, found := manager.ServiceForRegistration(id); !found || service.Registered || service.Failure != "runtime.cleanup_failed" {
		t.Fatal("failed cleanup released ownership or remained traffic-ready")
	}
	err = manager.UnregisterTarget(id, "owner", "http://127.0.0.1:3000")
	if !errors.Is(err, workerFailure) || !errors.Is(err, context.Canceled) || attempts.Load() != 3 {
		t.Fatal("retry hid independent canceled worker failure", err)
	}
	if _, found := manager.ServiceForRegistration(id); found {
		t.Fatal("successful cleanup retained registration")
	}
}

func TestInvocationDefinitionsStayBoundedWithoutEvictingConfiguredOrLiveServices(t *testing.T) {
	manager, err := newTestManager(t, t.TempDir(), t.TempDir(), []Service{{Name: "web"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	live, _ := opaqueid.New(opaqueid.InvocationPrefix)
	if err := manager.AddService(Service{Name: live}); err != nil {
		t.Fatal(err)
	}
	id, err := manager.Reserve(live, "owner", 1, "https://live.example")
	if err != nil {
		t.Fatal(err)
	}
	for range 520 {
		name, _ := opaqueid.New(opaqueid.InvocationPrefix)
		if err := manager.AddService(Service{Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := manager.Snapshot()
	if len(snapshot.Services) > 256 {
		t.Fatalf("unbounded invocation definitions: %d", len(snapshot.Services))
	}
	if service, found := manager.ServiceForRegistration(id); !found || service.Name != live {
		t.Fatal("live invocation evicted")
	}
	configured := false
	for _, service := range snapshot.Services {
		configured = configured || service.Name == "web"
	}
	if !configured {
		t.Fatal("configured service evicted")
	}
}
