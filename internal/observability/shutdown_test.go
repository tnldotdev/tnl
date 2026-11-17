package observability

import (
	"context"
	"testing"
	"testing/synctest"
	"time"
)

func TestShutdownDeadlineObserverCanOnlyNarrow(t *testing.T) {
	for _, test := range []struct {
		name     string
		parent   time.Duration
		observed time.Duration
		want     time.Duration
	}{
		{name: "later-observer", observed: time.Hour, want: 5 * time.Second},
		{name: "earlier-observer", observed: time.Second, want: time.Second},
		{name: "earlier-parent", parent: 3 * time.Second, observed: time.Hour, want: 3 * time.Second},
		{name: "earlier-than-parent", parent: 3 * time.Second, observed: time.Second, want: time.Second},
		{name: "expired-parent", parent: -time.Second, observed: time.Hour, want: -time.Second},
		{name: "expired-observer", observed: -time.Second, want: -time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				now := time.Now()
				ctx := t.Context()
				requested := now.Add(5 * time.Second)
				passed := requested
				if test.parent != 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithDeadline(ctx, now.Add(test.parent))
					defer cancel()
					if parent, _ := ctx.Deadline(); parent.Before(passed) {
						passed = parent
					}
				}
				ctx = WithShutdownDeadline(ctx, func(until time.Time) time.Time {
					if !until.Equal(passed) {
						t.Error("observer did not receive the already-narrowed request", until, passed)
					}
					return now.Add(test.observed)
				})
				got := ShutdownDeadline(ctx, requested)
				if want := now.Add(test.want); !got.Equal(want) {
					t.Error("observer replaced the requested or earlier parent deadline", got, want)
				}
			})
		})
	}
}
