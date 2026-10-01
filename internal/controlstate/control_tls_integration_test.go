package controlstate

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
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
	database, databaseURL, _ := newControlStateIntegrationDatabaseWithURL(t, "tls_leadership")
	otherDatabase, err := Open(t.Context(), databaseURL, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(otherDatabase.Close)
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
	if err := otherDatabase.RunControlTLSLeader(otherCtx, func(context.Context) error {
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

func TestIntegrationControlTLSLeadershipJoinsBeforeHandoff(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "tls_join_handoff")
	ctx, cancel := context.WithCancel(t.Context())
	workers := newIntegrationWorkers(t, cancel)
	started, stopping, finish := make(chan struct{}), make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(finish) })
	t.Cleanup(unblock)
	done := make(chan error, 1)
	workers.Go(func() {
		done <- database.RunControlTLSLeader(ctx, func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			close(stopping)
			<-finish
			return nil
		})
	})
	awaitIntegrationResult(t, t.Context(), started)
	cancel()
	awaitIntegrationResult(t, t.Context(), stopping)
	otherCtx, cancelOther := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancelOther()
	if err := database.RunControlTLSLeader(otherCtx, func(context.Context) error {
		t.Error("replacement acquired leadership before canceled callback finished")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	unblock()
	if err := awaitIntegrationResult(t, t.Context(), done); err != nil {
		t.Fatal(err)
	}
	if err := database.RunControlTLSLeader(t.Context(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("replacement after callback finished: %v", err)
	}
}

func TestIntegrationControlTLSLeadershipDoesNotConsumeApplicationPool(t *testing.T) {
	database, databaseURL, _ := newControlStateIntegrationDatabaseWithURL(t, "tls_leadership_pool")
	database.Close()
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	database = &Database{pool: pool, storageKey: database.storageKey}
	t.Cleanup(database.Close)
	cache, err := database.ControlTLSCache("https://acme.example.test/directory")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := database.RunControlTLSLeader(ctx, func(ctx context.Context) error {
		if err := cache.Put(ctx, "control.example.test", []byte("certificate state")); err != nil {
			return err
		}
		data, err := cache.Get(ctx, "control.example.test")
		if err != nil || !bytes.Equal(data, []byte("certificate state")) {
			return errors.New("control TLS cache round trip failed")
		}
		var sessions int
		if err := database.pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()`).Scan(&sessions); err != nil {
			return err
		}
		if sessions < 2 {
			return errors.New("leadership connection was not separately owned")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationControlTLSLeadershipConnectionLoss(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "tls_connection_loss")
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	started, canceled := make(chan struct{}, 2), make(chan struct{}, 2)
	done := make(chan error, 1)
	workers.Go(func() {
		done <- database.RunControlTLSLeader(ctx, func(ctx context.Context) error {
			started <- struct{}{}
			<-ctx.Done()
			canceled <- struct{}{}
			return nil
		})
	})
	awaitIntegrationResult(t, ctx, started)
	// advisory lock keys are reused in other test databases on the same server.
	// resolve exactly one holder in our database before terminating its backend.
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
	awaitIntegrationResult(t, ctx, canceled)
	awaitIntegrationResult(t, ctx, started)
	cancel()
	if err := awaitIntegrationResult(t, t.Context(), done); err != nil {
		t.Fatalf("leadership recovery returned %v", err)
	}
}

func TestIntegrationControlTLSLeadershipShutdownClosesConnection(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "tls_shutdown")
	ctx, cancel := context.WithCancel(t.Context())
	workers := newIntegrationWorkers(t, cancel)
	started := make(chan struct{})
	done := make(chan error, 1)
	workers.Go(func() {
		done <- database.RunControlTLSLeader(ctx, func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			return nil
		})
	})
	awaitIntegrationResult(t, t.Context(), started)
	var pid int32
	if err := database.pool.QueryRow(t.Context(), `
		SELECT pid FROM pg_locks
		WHERE locktype = 'advisory'
		  AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
		  AND classid::bigint = $1 AND objid::bigint = $2 AND objsubid = 1
		  AND granted AND pid <> pg_backend_pid()
	`, controlTLSLeadershipKey>>32, controlTLSLeadershipKey&0xffffffff).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := awaitIntegrationResult(t, t.Context(), done); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var sessions int
		if err := database.pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_stat_activity WHERE pid = $1`, pid).Scan(&sessions); err != nil {
			t.Fatal(err)
		}
		if sessions == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("leadership backend %d remained after shutdown", pid)
		}
		time.Sleep(time.Millisecond)
	}
}

// join the callback even if a startup or fault-injection assertion fails. this
// cleanup is registered after the worker group and before startup.
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
