package controlstate

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

func TestIntegrationControlTLSCache(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "control_tls_cache")
	cache, err := database.ControlTLSCache("https://acme.example.test/directory")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Get(t.Context(), "control.example.test"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("missing cache entry: %v", err)
	}
	want := []byte("certificate state")
	if err := cache.Put(t.Context(), "control.example.test", want); err != nil {
		t.Fatal(err)
	}
	var ciphertext []byte
	if err := database.pool.QueryRow(t.Context(), `SELECT cache_ciphertext FROM control.control_tls_cache
		WHERE directory_url = $1 AND cache_key = $2`, cache.directoryURL, "control.example.test").Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) == 0 || bytes.Contains(ciphertext, want) {
		t.Fatal("cache entry was not encrypted")
	}
	data, err := cache.Get(t.Context(), "control.example.test")
	if err != nil || !bytes.Equal(data, want) {
		t.Fatalf("cache round trip = %q, %v", data, err)
	}
	if err := cache.Delete(t.Context(), "control.example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Get(t.Context(), "control.example.test"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("deleted cache entry: %v", err)
	}
}

func TestIntegrationControlTLSLeadershipExclusionAndHandoff(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "tls_leadership")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	started, release, callbackDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	joinTLSCallbackOnCleanup(t, cancel, callbackDone)
	done := make(chan error, 1)
	workers.Go(func() {
		done <- database.RunControlTLSLeader(ctx, func(ctx context.Context) error {
			defer close(callbackDone)
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
			}
			return nil
		})
	})
	awaitIntegrationResult(t, ctx, started)
	otherCtx, cancelOther := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancelOther()
	otherRan := make(chan struct{}, 1)
	if err := database.RunControlTLSLeader(otherCtx, func(context.Context) error {
		otherRan <- struct{}{}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-otherRan:
		t.Fatal("two control TLS leaders ran concurrently")
	default:
	}
	unblock()
	if err := awaitIntegrationResult(t, ctx, done); err != nil {
		t.Fatal(err)
	}
	var ran atomic.Bool
	if err := database.RunControlTLSLeader(ctx, func(context.Context) error { ran.Store(true); return nil }); err != nil || !ran.Load() {
		t.Fatalf("replacement leader: ran %t, error %v", ran.Load(), err)
	}
}

func TestIntegrationControlTLSLeadershipConnectionLoss(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "tls_connection_loss")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	started, canceled := make(chan struct{}), make(chan struct{})
	joinTLSCallbackOnCleanup(t, cancel, canceled)
	done := make(chan error, 1)
	workers.Go(func() {
		done <- database.RunControlTLSLeader(ctx, func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			close(canceled)
			return nil
		})
	})
	awaitIntegrationResult(t, ctx, started)
	// Advisory lock keys are reused in other test databases on the same server.
	// Resolve exactly one holder in OUR database before terminating its backend.
	var pids []int32
	if err := database.pool.QueryRow(ctx, `
		SELECT array_agg(pid) FROM pg_locks
		WHERE locktype = 'advisory'
		  AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
		  AND classid::bigint = $1 AND objid::bigint = $2 AND objsubid = 1
		  AND granted AND pid <> pg_backend_pid()
	`, controlTLSLeadershipKey>>32, controlTLSLeadershipKey&0xffffffff).Scan(&pids); err != nil {
		t.Fatal(err)
	}
	if len(pids) != 1 {
		t.Fatalf("control TLS lock holders in test database = %v, want one", pids)
	}
	var terminated bool
	if err := database.pool.QueryRow(ctx, `
		SELECT pg_terminate_backend(pid) FROM pg_stat_activity
		WHERE pid = $1 AND datname = current_database()
	`, pids[0]).Scan(&terminated); err != nil || !terminated {
		t.Fatalf("terminate leader backend %d: %t, %v", pids[0], terminated, err)
	}
	if err := awaitIntegrationResult(t, ctx, done); err == nil {
		t.Fatal("leadership connection loss returned no error")
	}
	awaitIntegrationResult(t, ctx, canceled)
	var ran atomic.Bool
	if err := database.RunControlTLSLeader(ctx, func(context.Context) error { ran.Store(true); return nil }); err != nil || !ran.Load() {
		t.Fatalf("replacement after connection loss: ran %t, error %v", ran.Load(), err)
	}
}

// RunControlTLSLeader returns on cancellation without joining its callback.
// Join that callback separately, even if a startup or fault-injection assertion
// fails. This cleanup is registered after the worker group and before startup.
func joinTLSCallbackOnCleanup(t *testing.T, cancel context.CancelFunc, done <-chan struct{}) {
	t.Helper()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("control TLS callback did not finish during cleanup")
		}
	})
}
