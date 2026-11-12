package state

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestServiceBrowserRefreshRetryBoundary(t *testing.T) {
	conflict := &pgconn.PgError{Code: "55P03"}
	busy := &serviceBrowserRefreshBusy{cause: conflict}
	cleanup := errors.New("independent rollback failure")
	for _, test := range []struct {
		name  string
		err   error
		retry bool
	}{
		{"initial clean conflict", busy, true},
		{"joined rollback failure", errors.Join(busy, cleanup), false},
		{"rollback failure before conflict", errors.Join(cleanup, busy), false},
		{"wrapped conflict", fmt.Errorf("later work: %w", busy), false},
		{"callback or later lock conflict", conflict, false},
		{"callback or later serialization failure", &pgconn.PgError{Code: "40001"}, false},
		{"callback or later deadlock", &pgconn.PgError{Code: "40P01"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				clock := newAuthorizationClock(time.Now().Add(time.Hour))
				calls := 0
				result, err := retryServiceBrowserRefresh(t.Context(), clock, func(_ context.Context, got authorizationClock) (BrowserAccessSession, error) {
					calls++
					if got != clock {
						t.Fatal("retry restarted the entry authorization clock")
					}
					if calls == 1 {
						return BrowserAccessSession{IdentityID: "must-not-escape"}, test.err
					}
					return BrowserAccessSession{IdentityID: "success"}, nil
				})
				if test.retry {
					if calls != 2 || err != nil || result.IdentityID != "success" {
						t.Fatal("clean initial conflict did not retry", calls, err)
					}
				} else if calls != 1 || !errors.Is(err, test.err) || result.IdentityID != "" {
					t.Fatal("replayed or discarded an independent failure", calls, err)
				}
			})
		})
	}
	// the real cleanup helper joins failures after the marked initial conflict.
	t.Run("actual rollback failure", func(t *testing.T) {
		calls := 0
		_, err := retryServiceBrowserRefresh(t.Context(), newAuthorizationClock(time.Now()), func(ctx context.Context, _ authorizationClock) (BrowserAccessSession, error) {
			calls++
			var retErr error = busy
			rollback(ctx, &rollbackTransaction{t: t, failure: cleanup}, "browser refresh fixture", &retErr)()
			return BrowserAccessSession{}, retErr
		})
		if calls != 1 || !errors.Is(err, cleanup) || !errors.Is(err, conflict) {
			t.Fatal("rollback failure was retried or lost", calls, err)
		}
	})
}

func TestServiceBrowserRefreshBudgetAndCancellation(t *testing.T) {
	for _, budget := range []time.Duration{20 * time.Second, 30 * time.Millisecond} {
		t.Run(budget.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx := t.Context()
				if budget < 20*time.Second {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, budget)
					defer cancel()
				}
				started := time.Now()
				clock := newAuthorizationClock(started.Add(time.Hour))
				calls := 0
				conflict := &pgconn.PgError{Code: "55P03"}
				_, err := retryServiceBrowserRefresh(ctx, clock, func(ctx context.Context, got authorizationClock) (BrowserAccessSession, error) {
					calls++
					deadline, ok := ctx.Deadline()
					if !ok || !deadline.Equal(started.Add(budget)) || got != clock {
						t.Fatal("retry extended the operation budget or restarted its clock")
					}
					return BrowserAccessSession{}, &serviceBrowserRefreshBusy{cause: conflict}
				})
				if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, conflict) || time.Since(started) != budget || clock.current().Sub(clock.entered) != budget {
					t.Fatal("contention lost deadline/cause or changed the entry clock", err)
				}
				if budget == 20*time.Second && calls <= 8 {
					t.Fatal("contention retained the short attempt-count limit", calls)
				}
			})
		})
	}
	t.Run("cancellation preserves independent failure", func(t *testing.T) {
		cause, failure := errors.New("caller stopped"), errors.New("callback failed independently")
		ctx, cancel := context.WithCancelCause(t.Context())
		defer cancel(nil)
		calls := 0
		result, err := retryServiceBrowserRefresh(ctx, newAuthorizationClock(time.Now()), func(context.Context, authorizationClock) (BrowserAccessSession, error) {
			calls++
			cancel(cause)
			return BrowserAccessSession{IdentityID: "must-not-escape"}, failure
		})
		if calls != 1 || result.IdentityID != "" || !errors.Is(err, cause) || !errors.Is(err, failure) {
			t.Fatal("cancellation hid failure or returned stale success", err)
		}
	})
}
