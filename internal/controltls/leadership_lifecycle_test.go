package controltls

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type lifecycleRoundTripper func(*http.Request) (*http.Response, error)

func (f lifecycleRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestLeadershipCancellationStopsInFlightIssuance(t *testing.T) {
	for _, test := range []struct {
		name              string
		shutdown, renewal bool
	}{
		{name: "leadership_loss"},
		{name: "shutdown", shutdown: true},
		{name: "renewal_leadership_loss", renewal: true},
		{name: "renewal_shutdown", shutdown: true, renewal: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, stop := context.WithCancel(t.Context())
				defer stop()
				leaderCtx, loseLeadership := context.WithCancel(ctx)
				defer loseLeadership()
				requestStarted := make(chan context.Context, 1)
				release := make(chan struct{})
				cache := newMemoryCache()
				if test.renewal {
					now := time.Now()
					if err := cache.Put(t.Context(), "control.example", testCertificateValidity(t, "control.example", now.Add(-time.Hour), now.Add(time.Minute))); err != nil {
						t.Fatal(err)
					}
				}
				source, err := New(Config{
					Hostname: "control.example", Cache: cache, DirectoryURL: "https://acme.example/directory",
					Email: "operator@example.com", AcceptTerms: true, AccountKey: testAccountKey(t),
					RunLeader: func(_ context.Context, run func(context.Context) error) error { return run(leaderCtx) },
					HTTPClient: &http.Client{Transport: lifecycleRoundTripper(func(request *http.Request) (*http.Response, error) {
						requestStarted <- request.Context()
						select {
						case <-request.Context().Done():
							return nil, request.Context().Err()
						case <-release:
							return nil, errors.New("test released blocked ACME request")
						}
					})},
				})
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- source.Run(ctx) }()
				requestCtx := <-requestStarted
				if test.renewal && !source.Ready(time.Now()) {
					t.Error("in-flight renewal made the valid cached certificate unavailable")
				}
				if test.shutdown {
					stop()
				} else {
					loseLeadership()
				}
				synctest.Wait()
				if requestCtx.Err() == nil {
					t.Error("ACME request is still live after leadership cancellation")
				}
				select {
				case err := <-done:
					if err != nil && !errors.Is(err, context.Canceled) {
						t.Errorf("Run: %v", err)
					}
					close(release)
				default:
					t.Error("Run has not finished after leadership cancellation")
					// Unblock the broken implementation so the reproduction owns
					// and joins its goroutine even when the assertions fail.
					close(release)
					<-done
				}
			})
		})
	}
}

func TestStoppedSourceDoesNotStartCertificateRenewal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cache := newMemoryCache()
		if err := cache.Put(t.Context(), "control.example", testCertificate(t, "control.example")); err != nil {
			t.Fatal(err)
		}
		var requests atomic.Int32
		source, err := New(Config{
			Hostname: "control.example", Cache: cache, DirectoryURL: "https://acme.example/directory",
			Email: "operator@example.com", AcceptTerms: true, AccountKey: testAccountKey(t),
			RunLeader: func(ctx context.Context, run func(context.Context) error) error { return run(ctx) },
			HTTPClient: &http.Client{Transport: lifecycleRoundTripper(func(request *http.Request) (*http.Response, error) {
				requests.Add(1)
				<-request.Context().Done()
				return nil, request.Context().Err()
			})},
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, stop := context.WithCancel(t.Context())
		defer stop()
		done := make(chan error, 1)
		go func() { done <- source.Run(ctx) }()
		// With usable cached material, Run reaches its wait without ACME I/O.
		synctest.Wait()
		if requests.Load() != 0 {
			t.Fatal("fixture unexpectedly required initial issuance")
		}
		stop()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		// Advance past the cached certificate's renewal window and expiry.
		// No real clock wait or external CA is involved.
		time.Sleep(2 * time.Hour)
		if got := requests.Load(); got != 0 {
			t.Errorf("stopped source started %d ACME requests after Run returned", got)
		}
	})
}

func TestScheduledRenewalStopsWithLeadership(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cache := newMemoryCache()
		if err := cache.Put(t.Context(), "control.example", testCertificate(t, "control.example")); err != nil {
			t.Fatal(err)
		}
		requests := make(chan context.Context, 4)
		source, err := New(Config{
			Hostname: "control.example", Cache: cache, DirectoryURL: "https://acme.example/directory",
			Email: "operator@example.com", AcceptTerms: true, AccountKey: testAccountKey(t),
			RunLeader: func(ctx context.Context, run func(context.Context) error) error { return run(ctx) },
			HTTPClient: &http.Client{Transport: lifecycleRoundTripper(func(request *http.Request) (*http.Response, error) {
				requests <- request.Context()
				<-request.Context().Done()
				return nil, request.Context().Err()
			})},
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, stop := context.WithCancel(t.Context())
		defer stop()
		done := make(chan error, 1)
		go func() { done <- source.Run(ctx) }()
		synctest.Wait()
		if len(requests) != 0 {
			t.Error("fresh cached certificate triggered issuance")
		}
		// A one-hour certificate enters its renewal window after about
		// forty minutes. Exercise the timer, not a direct issuance call.
		time.Sleep(40 * time.Minute)
		synctest.Wait()
		var requestCtx context.Context
		select {
		case requestCtx = <-requests:
			if requestCtx.Err() != nil {
				t.Error("renewal request ended before leadership was canceled")
			}
		default:
			t.Error("scheduled renewal never started")
		}
		stop()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if requestCtx != nil && requestCtx.Err() == nil {
			t.Error("scheduled renewal request survived leadership cancellation")
		}
		time.Sleep(2 * time.Hour)
		if len(requests) != 0 {
			t.Error("scheduled renewal restarted after Run returned")
		}
	})
}
