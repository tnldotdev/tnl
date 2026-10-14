package clientruntime

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
)

func TestNamedLeaseSharesManagerAndFencesReplacedTargets(t *testing.T) {
	var runs atomic.Uint64
	started := make(chan Service, 3)
	m, err := New(t.Context(), t.TempDir(), testManagerState(t), []Service{
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
	defer m.Close()
	id, err := m.Reserve("orders", "cli-owner", os.Getpid(), "orders.example:15432")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Register(id, "cli-owner", "http://127.0.0.1:5432", "node"); err == nil {
		t.Fatal("app registration claimed named TCP service")
	}
	for _, target := range []string{"http://127.0.0.1:5432", "5432", "db:0"} {
		if err := m.RegisterNamed(id, "cli-owner", target); err == nil {
			t.Fatalf("accepted invalid target %q", target)
		}
	}
	if err := m.RegisterNamed(id, "cli-owner", "127.0.0.1:5432"); err != nil {
		t.Fatal(err)
	}
	first := <-started
	if first.ServiceProtocol != "postgres" || first.Framework != "" || !m.Current("orders", id, first.Target, 1) {
		t.Fatalf("named lease = %+v", first)
	}
	if _, err := m.Reserve("orders", "other", os.Getpid(), "orders.example:15432"); !errors.Is(err, ErrOwnerConflict) {
		t.Fatalf("second owner = %v", err)
	}
	if err := m.RegisterNamed(id, "cli-owner", "127.0.0.1:5433"); err != nil {
		t.Fatal(err)
	}
	second := <-started
	if second.Target != "127.0.0.1:5433" || m.Current("orders", id, first.Target, 1) || !m.Current("orders", id, second.Target, 2) {
		t.Fatalf("replacement = %+v", second)
	}
	appID, err := m.Reserve("web", "app-owner", os.Getpid(), "https://web.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Register(appID, "app-owner", "http://127.0.0.1:3000", "node"); err != nil {
		t.Fatal(err)
	}
	app := <-started
	if app.Name != "web" || !m.Current("web", appID, app.Target, 3) {
		t.Fatalf("app = %+v", app)
	}
	if err := m.Unregister(id, "cli-owner"); err != nil || m.Current("orders", id, second.Target, 2) {
		t.Fatalf("stop named = %v", err)
	}
	if !m.Current("web", appID, app.Target, 3) {
		t.Fatal("named stop also stopped app")
	}
	if err := m.Renew(id, "cli-owner"); !errors.Is(err, ErrRegistrationStale) {
		t.Fatalf("stale renewal = %v", err)
	}
	if _, err := m.Reserve("orders", "new-owner", os.Getpid(), "orders.example:15432"); err != nil {
		t.Fatal(err)
	}
}

func TestNamedHTTPRequiresCanonicalOriginAndCannotClaimApp(t *testing.T) {
	m, err := New(t.Context(), t.TempDir(), testManagerState(t), []Service{{Name: "api", ServiceProtocol: "http"}, {Name: "web"}},
		func(ctx context.Context, _ Service, _ func(uint64, bool) error) error { <-ctx.Done(); return ctx.Err() })
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	id, err := m.Reserve("api", "cli", os.Getpid(), "https://api.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Register(id, "cli", "http://127.0.0.1:3000", "node"); err == nil {
		t.Fatal("app claimed named HTTP service")
	}
	if err := m.RegisterNamed(id, "cli", "127.0.0.1:3000"); err == nil {
		t.Fatal("accepted bare TCP address for HTTP")
	}
	if err := m.RegisterNamed(id, "cli", "http://127.0.0.1:3000"); err != nil {
		t.Fatal(err)
	}
	webID, err := m.Reserve("web", "app", os.Getpid(), "https://web.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.RegisterNamed(webID, "app", "http://127.0.0.1:3001"); err == nil {
		t.Fatal("named registration claimed app")
	}
	if err := m.Configure([]Service{{Name: "api", ServiceProtocol: "postgres"}, {Name: "web"}}); err == nil {
		t.Fatal("changed live named protocol")
	}
}

func TestConcurrentNamedClaimHasOneOwner(t *testing.T) {
	m, err := New(t.Context(), t.TempDir(), testManagerState(t), []Service{{Name: "orders", ServiceProtocol: "postgres"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	var wg sync.WaitGroup
	var winners atomic.Int32
	for _, owner := range []string{"first", "second"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.Reserve("orders", owner, os.Getpid(), "orders.example:15432"); err == nil {
				winners.Add(1)
			} else if !errors.Is(err, ErrOwnerConflict) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("claimed by %d owners", winners.Load())
	}
}

func TestNamedLeaseReacquiresAfterOwnerReplacement(t *testing.T) {
	project, state := t.TempDir(), testManagerState(t)
	services := []Service{{Name: "orders", ServiceProtocol: "postgres"}, {Name: "web"}}
	run := func(ctx context.Context, _ Service, observe func(uint64, bool) error) error {
		if err := observe(1, true); err != nil {
			return err
		}
		<-ctx.Done()
		return ctx.Err()
	}
	first, err := New(t.Context(), project, state, services, run)
	if err != nil {
		t.Fatal(err)
	}
	id, err := first.Reserve("orders", "owner", os.Getpid(), "orders.example:15432")
	if err != nil {
		t.Fatal(err)
	}
	if err := first.RegisterNamed(id, "owner", "127.0.0.1:5432"); err != nil {
		t.Fatal(err)
	}
	first.Close()
	second, err := New(t.Context(), project, state, services, run)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := second.Renew(id, "owner"); !errors.Is(err, ErrRegistrationStale) {
		t.Fatalf("old lease renewed: %v", err)
	}
	replacement, err := second.Reserve("orders", "owner", os.Getpid(), "orders.example:15432")
	if err != nil || replacement == id {
		t.Fatalf("replaced ID = %s, %v", replacement, err)
	}
	if err := second.Started(id, "127.0.0.1:5432", "tun_old"); !errors.Is(err, ErrRegistrationStale) {
		t.Fatalf("old worker started: %v", err)
	}
	if err := second.RecordPublication(id, "127.0.0.1:5432", PublicationEvent{Type: "ready"}); !errors.Is(err, ErrRegistrationStale) {
		t.Fatalf("old worker recorded progress: %v", err)
	}
	if err := second.RegisterNamed(replacement, "owner", "127.0.0.1:5432"); err != nil {
		t.Fatal(err)
	}
	if err := second.Started(replacement, "127.0.0.1:5433", "tun_wrong_target"); !errors.Is(err, ErrRegistrationStale) {
		t.Fatalf("wrong target started: %v", err)
	}
	if err := second.Started(replacement, "127.0.0.1:5432", "tun_current"); err != nil {
		t.Fatal(err)
	}
	if err := second.RecordPublication(replacement, "127.0.0.1:5433", PublicationEvent{Type: "ready"}); !errors.Is(err, ErrRegistrationStale) {
		t.Fatalf("wrong target recorded progress: %v", err)
	}
	if err := second.RecordPublication(replacement, "127.0.0.1:5432", PublicationEvent{Type: "provisioning", Hostname: "orders.example"}); err != nil {
		t.Fatal(err)
	}
	if got := second.Snapshot().Services[0]; got.TunnelID != "tun_current" {
		t.Fatalf("replaced owner = %+v", got)
	}
	snapshot, err := second.JournalSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EventsAfter(snapshot, "0"); err != nil {
		t.Fatalf("owner replacement lost journal history: %v", err)
	}
}
