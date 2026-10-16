package livevisitor

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func testKey() Key {
	return Key{PublicURLID: "url", PublishRunID: "run", PublishRunNumber: 1,
		SourceIP: netip.MustParseAddr("192.0.2.1"), CertificateSHA256: sha256.Sum256([]byte("certificate"))}
}

func assertLive(t *testing.T, lease *Lease) {
	t.Helper()
	select {
	case <-lease.Done():
		t.Fatal("permission closed before its deadline")
	default:
	}
}

func assertClosed(t *testing.T, lease *Lease) {
	t.Helper()
	select {
	case <-lease.Done():
	default:
		t.Fatal("permission remained live after denial or expiration")
	}
}

func TestActiveProofSharesChecksAndDenial(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var group Group
		defer group.Close()
		var calls atomic.Int32
		check := func(context.Context) (Decision, error) {
			return Decision{Allowed: calls.Add(1) == 1, IdentityID: "identity", ValidUntil: time.Now().Add(MaxLifetime)}, nil
		}
		var leases [20]*Lease
		var workers sync.WaitGroup
		for i := range leases {
			workers.Go(func() {
				lease, _, err := group.Acquire(t.Context(), testKey(), check)
				if err != nil {
					t.Error(err)
					return
				}
				leases[i] = lease
			})
		}
		workers.Wait()
		if calls.Load() != 1 {
			t.Fatal("concurrent sessions did not share one check")
		}
		time.Sleep(RefreshInterval - time.Nanosecond)
		synctest.Wait()
		for _, lease := range leases {
			assertLive(t, lease)
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if calls.Load() != 2 {
			t.Fatal("active sessions were not rechecked after 30 seconds")
		}
		for _, lease := range leases {
			assertClosed(t, lease)
			lease.Close()
		}
		group.mu.Lock()
		defer group.mu.Unlock()
		if len(group.entries) != 0 {
			t.Fatal("inactive proof was retained")
		}
	})
}

func TestTransientCheckRejectsNewSessionsWithoutExtendingDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var group Group
		defer group.Close()
		until := time.Now().Add(45 * time.Second)
		calls := 0
		unavailable := errors.New("authority unavailable")
		check := func(context.Context) (Decision, error) {
			calls++
			if calls > 1 {
				return Decision{}, unavailable
			}
			return Decision{Allowed: true, ValidUntil: until}, nil
		}
		lease, _, err := group.Acquire(t.Context(), testKey(), check)
		if err != nil {
			t.Fatal(err)
		}
		defer lease.Close()
		time.Sleep(RefreshInterval)
		synctest.Wait()
		assertLive(t, lease)
		if added, _, err := group.Acquire(t.Context(), testKey(), check); !errors.Is(err, unavailable) {
			if added != nil {
				added.Close()
			}
			t.Fatalf("new session reused an unknown result: %v", err)
		}
		time.Sleep(time.Until(until) - time.Nanosecond)
		synctest.Wait()
		assertLive(t, lease)
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		assertClosed(t, lease)
	})
}

func TestHardExpiryClosesWhileRefreshIsBlockedAndJoinsChecker(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var group Group
		defer group.Close()
		calls := 0
		joined := make(chan struct{})
		var once sync.Once
		check := func(ctx context.Context) (Decision, error) {
			calls++
			if calls == 1 {
				return Decision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
			}
			<-ctx.Done()
			once.Do(func() { close(joined) })
			return Decision{}, ctx.Err()
		}
		lease, _, err := group.Acquire(t.Context(), testKey(), check)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		assertClosed(t, lease)
		lease.Close()
		select {
		case <-joined:
		default:
			t.Fatal("last connection left a checker running")
		}
	})
}

func TestGrantExpiryAndMaximumLifetime(t *testing.T) {
	for _, lifetime := range []time.Duration{3 * time.Second, time.Hour} {
		t.Run(lifetime.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var group Group
				defer group.Close()
				calls := 0
				started := time.Now()
				lease, decision, err := group.Acquire(t.Context(), testKey(), func(context.Context) (Decision, error) {
					calls++
					if calls > 1 {
						return Decision{}, errors.New("offline")
					}
					return Decision{Allowed: true, ValidUntil: started.Add(lifetime)}, nil
				})
				if err != nil {
					t.Fatal(err)
				}
				defer lease.Close()
				if decision.ValidUntil != started.Add(min(lifetime, MaxLifetime)) {
					t.Fatal("permission exceeded the grant or maximum lifetime")
				}
				time.Sleep(time.Until(decision.ValidUntil))
				synctest.Wait()
				assertClosed(t, lease)
			})
		})
	}
}

func TestShortRunDeadlineRefreshesBeforeExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var group Group
		defer group.Close()
		checks := 0
		lease, _, err := group.Acquire(t.Context(), testKey(), func(context.Context) (Decision, error) {
			checks++
			return Decision{Allowed: true, ValidUntil: time.Now().Add(10 * time.Second)}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		defer lease.Close()
		time.Sleep(25 * time.Second)
		synctest.Wait()
		assertLive(t, lease)
		if checks < 3 || checks > 6 {
			t.Fatalf("short run lease made %d checks", checks)
		}
	})
}

func TestProofNeverSharesAnotherRunSourceCertificateOrSSHAccount(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var group Group
		defer group.Close()
		calls := 0
		check := func(context.Context) (Decision, error) {
			calls++
			return Decision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
		}
		keys := []Key{testKey(), testKey(), testKey(), testKey(), testKey(), testKey(), testKey()}
		keys[1].PublicURLID = "other-url"
		keys[2].PublishRunID = "other-run"
		keys[3].PublishRunNumber++
		keys[4].SourceIP = netip.MustParseAddr("192.0.2.2")
		keys[5].CertificateSHA256 = sha256.Sum256([]byte("other certificate"))
		keys[6].SSHUser = "deploy"
		for _, key := range keys {
			lease, _, err := group.Acquire(t.Context(), key, check)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Close()
		}
		if calls != len(keys) {
			t.Fatal("different scoped proof reused an authorization")
		}
	})
}

func TestCancellationOfOneWaiterAndRunShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var group Group
		ctx, cancel := context.WithCancel(t.Context())
		release := make(chan struct{})
		check := func(ctx context.Context) (Decision, error) {
			select {
			case <-release:
				return Decision{Allowed: true, ValidUntil: time.Now().Add(time.Minute)}, nil
			case <-ctx.Done():
				return Decision{}, ctx.Err()
			}
		}
		cancelled := make(chan error, 1)
		go func() { _, _, err := group.Acquire(ctx, testKey(), check); cancelled <- err }()
		var live *Lease
		go func() {
			var err error
			live, _, err = group.Acquire(t.Context(), testKey(), check)
			if err != nil {
				t.Error(err)
			}
		}()
		synctest.Wait()
		cancel()
		if err := <-cancelled; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		close(release)
		synctest.Wait()
		assertLive(t, live)
		group.Close()
		assertClosed(t, live)
		live.Close()
	})
}

func TestRefreshDoesNotAdmitNewSessionsFromAnOldDecision(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var group Group
		defer group.Close()
		checks := 0
		release := make(chan struct{})
		check := func(ctx context.Context) (Decision, error) {
			checks++
			if checks == 1 {
				return Decision{Allowed: true, ValidUntil: time.Now().Add(MaxLifetime)}, nil
			}
			select {
			case <-release:
				return Decision{}, nil
			case <-ctx.Done():
				return Decision{}, ctx.Err()
			}
		}
		lease, _, err := group.Acquire(t.Context(), testKey(), check)
		if err != nil {
			t.Fatal(err)
		}
		defer lease.Close()
		time.Sleep(RefreshInterval)
		synctest.Wait()
		added := make(chan error, 1)
		go func() {
			lease, _, err := group.Acquire(t.Context(), testKey(), check)
			if lease != nil {
				lease.Close()
			}
			added <- err
		}()
		synctest.Wait()
		select {
		case err := <-added:
			t.Fatalf("in-flight refresh did not gate the new session: %v", err)
		default:
		}
		assertLive(t, lease)
		close(release)
		if err := <-added; !errors.Is(err, ErrDenied) {
			t.Fatal(err)
		}
		assertClosed(t, lease)
	})
}

func TestCloseCancelsAndJoinsInFlightRefresh(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var group Group
		checks := 0
		returned := make(chan struct{})
		lease, _, err := group.Acquire(t.Context(), testKey(), func(ctx context.Context) (Decision, error) {
			checks++
			if checks == 1 {
				return Decision{Allowed: true, ValidUntil: time.Now().Add(MaxLifetime)}, nil
			}
			<-ctx.Done()
			defer close(returned)
			return Decision{}, ctx.Err()
		})
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(RefreshInterval)
		synctest.Wait()
		group.Close()
		assertClosed(t, lease)
		select {
		case <-returned:
		default:
			t.Fatal("run shutdown did not join its in-flight checker")
		}
		lease.Close()
	})
}
