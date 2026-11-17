package observability

import (
	"context"
	"time"
)

type shutdownDeadlineKey struct{}

// WithShutdownDeadline hands process-owned stop deadlines back to the final
// export owner. it starts no worker and owns no cancellation, drain, or join.
func WithShutdownDeadline(ctx context.Context, limit func(time.Time) time.Time) context.Context {
	return context.WithValue(ctx, shutdownDeadlineKey{}, limit)
}

// ShutdownDeadline retains an earlier parent deadline before handing off the
// operation owner's original stop limit. an observer may only narrow that limit;
// callers keep their existing cleanup.
func ShutdownDeadline(ctx context.Context, until time.Time) time.Time {
	if parent, ok := ctx.Deadline(); ok && parent.Before(until) {
		until = parent
	}
	if limit, ok := ctx.Value(shutdownDeadlineKey{}).(func(time.Time) time.Time); ok {
		if observed := limit(until); observed.Before(until) {
			until = observed
		}
	}
	return until
}
