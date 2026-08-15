package controltls

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

type blockedCache struct {
	autocert.Cache
	get   func(context.Context, string) ([]byte, error)
	calls atomic.Int64
}

func (c *blockedCache) Get(ctx context.Context, key string) ([]byte, error) {
	c.calls.Add(1)
	return c.get(ctx, key)
}

func refreshTestSource(t *testing.T, cache autocert.Cache) *Source {
	t.Helper()
	source, err := New(Config{Hostname: "control.example", Cache: cache, DirectoryURL: "https://acme.example/directory", Email: "test@example.com", AccountKey: testAccountKey(t),
		RunLeader: func(ctx context.Context, _ func(context.Context) error) error { <-ctx.Done(); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func TestCertificateRefreshDoesNotBlockValidHandshakes(t *testing.T) {
	data := testCertificate(t, "control.example")
	renewed := testCertificate(t, "control.example")
	entered, release := make(chan struct{}, 2), make(chan error, 2)
	cache := &blockedCache{get: func(ctx context.Context, _ string) ([]byte, error) {
		entered <- struct{}{}
		select {
		case err := <-release:
			if err != nil {
				return nil, err
			}
			return renewed, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	source := refreshTestSource(t, cache)
	certificate, err := tls.X509KeyPair(data, data)
	if err != nil {
		t.Fatal(err)
	}
	source.certificates["control.example"] = &certificate
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- source.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	hello := &tls.ClientHelloInfo{ServerName: "control.example"}
	if got, err := source.GetCertificate(hello); err != nil || got != &certificate {
		t.Fatalf("valid cached certificate = %p, %v", got, err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("refresh did not start")
	}
	var handshakes sync.WaitGroup
	for range 64 {
		handshakes.Go(func() {
			if got, err := source.GetCertificate(hello); err != nil || got != &certificate {
				t.Errorf("blocked healthy handshake: %p, %v", got, err)
			}
		})
	}
	finished := make(chan struct{})
	go func() { handshakes.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("healthy handshakes waited for cache")
	}
	if cache.calls.Load() != 1 {
		t.Fatalf("refresh calls = %d", cache.calls.Load())
	}
	source.mu.RLock()
	load := source.loading["control.example"]
	source.mu.RUnlock()
	release <- errors.New("database unavailable")
	<-load.done
	for range 64 {
		if _, err := source.GetCertificate(hello); err != nil {
			t.Fatal(err)
		}
	}
	if cache.calls.Load() != 1 {
		t.Fatal("failed refresh did not back off")
	}
	if !source.Ready(time.Now()) {
		t.Fatal("valid source is not ready")
	}
	source.mu.Lock()
	source.refreshAt["control.example"] = time.Time{}
	source.mu.Unlock()
	if _, err := source.GetCertificate(hello); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("refresh retry did not start")
	}
	source.mu.RLock()
	load = source.loading["control.example"]
	source.mu.RUnlock()
	release <- nil
	<-load.done
	got, err := source.GetCertificate(hello)
	if err != nil || got == &certificate || string(got.Certificate[0]) == string(certificate.Certificate[0]) {
		t.Fatalf("renewal not propagated: %v", err)
	}
}

func TestCertificateInitialLoadValidityAndBackoff(t *testing.T) {
	now := time.Now()
	for _, test := range []struct {
		name, hostname string
		before, after  time.Time
	}{
		{"expired", "control.example", now.Add(-time.Hour), now.Add(-time.Second)},
		{"future", "control.example", now.Add(time.Hour), now.Add(2 * time.Hour)},
		{"hostname", "other.example", now.Add(-time.Hour), now.Add(time.Hour)},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := testCertificateValidity(t, test.hostname, test.before, test.after)
			cache := &blockedCache{get: func(context.Context, string) ([]byte, error) { return data, nil }}
			source := refreshTestSource(t, cache)
			for range 3 {
				if cert, err := source.GetCertificate(&tls.ClientHelloInfo{ServerName: "control.example"}); err == nil || cert != nil {
					t.Fatal("served invalid certificate")
				}
			}
			if source.Ready(now) {
				t.Fatal("invalid source is ready")
			}
			if cache.calls.Load() != 1 {
				t.Fatal("failed initial load did not back off")
			}
		})
	}
}

func TestCertificateInitialLoadCoalescesAndShutdownCancelsRefresh(t *testing.T) {
	entered := make(chan struct{}, 1)
	cache := &blockedCache{get: func(ctx context.Context, _ string) ([]byte, error) {
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	source := refreshTestSource(t, cache)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	first := make(chan error, 1)
	go func() { _, err := source.refreshCertificate(ctx, "control.example", time.Now()); first <- err }()
	<-entered
	var callers sync.WaitGroup
	for range 32 {
		callers.Go(func() {
			if cert, err := source.GetCertificate(&tls.ClientHelloInfo{ServerName: "control.example"}); err == nil || cert != nil {
				t.Error("cache miss served material")
			}
		})
	}
	cancel()
	callers.Wait()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("load cancellation = %v", err)
	}
	if cache.calls.Load() != 1 {
		t.Fatalf("initial loads = %d", cache.calls.Load())
	}

	// A refresh started by Run is canceled and joined when Run stops.
	data := testCertificate(t, "control.example")
	certificate, err := tls.X509KeyPair(data, data)
	if err != nil {
		t.Fatal(err)
	}
	source.mu.Lock()
	source.certificates["control.example"] = &certificate
	source.refreshAt["control.example"] = time.Time{}
	source.mu.Unlock()
	runCtx, stop := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- source.Run(runCtx) }()
	if _, err := source.GetCertificate(&tls.ClientHelloInfo{ServerName: "control.example"}); err != nil {
		t.Fatal(err)
	}
	<-entered
	stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not join refresh")
	}
}

func TestCertificateExpiringDuringLoadIsNeverReturned(t *testing.T) {
	now := time.Now()
	expires := now.Truncate(time.Second).Add(time.Second)
	data := testCertificateValidity(t, "control.example", now.Add(-time.Minute), expires)
	entered, release := make(chan struct{}), make(chan struct{})
	cache := &blockedCache{get: func(ctx context.Context, _ string) ([]byte, error) {
		close(entered)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
			return data, nil
		}
	}}
	source := refreshTestSource(t, cache)
	done := make(chan error, 1)
	go func() {
		_, err := source.GetCertificate(&tls.ClientHelloInfo{ServerName: "control.example"})
		done <- err
	}()
	<-entered
	timer := time.NewTimer(time.Until(expires))
	defer timer.Stop()
	<-timer.C
	close(release)
	if err := <-done; err == nil {
		t.Fatal("certificate expired during load was served")
	}
	if source.Ready(time.Now()) {
		t.Fatal("expired source is ready")
	}
}
