package invocation

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
)

func TestPublicationShutdownHandsOriginalDeadlineToProcess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var recorded time.Time
		parent := observability.WithShutdownDeadline(t.Context(), func(until time.Time) time.Time {
			recorded = until
			return until
		})
		ctx, deadline, _, join := publicationShutdown(parent)
		defer join()
		until := deadline()
		<-ctx.Done()
		if !recorded.Equal(until) || time.Until(until) != 10*time.Second {
			t.Fatal("publication cleanup did not hand its original budget to the process", until, recorded)
		}
		time.Sleep(3 * time.Second)
		if got := deadline(); !got.Equal(until) {
			t.Fatal("publication started another cleanup window", got, until)
		}
	})
}

func TestPublicationShutdownRetainsEarlierParentAndExpiredProcessBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		parentUntil := time.Now().Add(time.Second)
		parent, cancel := context.WithDeadline(t.Context(), parentUntil)
		defer cancel()
		var recorded time.Time
		parent = observability.WithShutdownDeadline(parent, func(until time.Time) time.Time {
			recorded = until
			return until
		})
		ctx, deadline, _, join := publicationShutdown(parent)
		defer join()
		<-ctx.Done()
		if got := deadline(); !got.Equal(parentUntil) || !recorded.Equal(parentUntil) {
			t.Fatal("publication extended its expired parent budget", got, recorded)
		}
		cleanup, stop := context.WithDeadline(context.WithoutCancel(ctx), deadline())
		defer stop()
		if cleanup.Err() != context.DeadlineExceeded {
			t.Fatal("publication cleanup received a fresh window after parent expiry")
		}
	})
}

func TestPublicationShutdownFenceExpiresAtOriginalBound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		until := time.Now().Add(time.Second)
		parent := observability.WithShutdownDeadline(t.Context(), func(time.Time) time.Time { return until })
		ctx, deadline, fence, join := publicationShutdown(parent)
		defer join()
		if got := deadline(); got != until {
			t.Fatal("publication did not retain its process bound", got, until)
		}
		<-ctx.Done()
		if fence.Err() != nil {
			t.Fatal("stop request expired the cleanup fence before its deadline")
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if context.Cause(fence) != context.DeadlineExceeded || deadline() != until {
			t.Fatal("cleanup fence lost the original expiry or started a new budget", context.Cause(fence), deadline())
		}
		join()
		if context.Cause(fence) != context.DeadlineExceeded {
			t.Fatal("joining the fence replaced its expiry cause")
		}
	})
}
