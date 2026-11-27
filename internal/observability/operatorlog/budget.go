package operatorlog

import (
	"context"
	"sync/atomic"

	"github.com/tnldotdev/tnl/internal/observability"
	"golang.org/x/time/rate"
)

// Budget bounds event samples without dropping their aggregate count.
type Budget struct {
	limit      *rate.Limiter
	suppressed atomic.Int64
}

func NewBudget(perSecond rate.Limit, burst int) *Budget {
	return &Budget{limit: rate.NewLimiter(perSecond, burst)}
}

// Take returns the number of suppressed samples since the last permitted
// line. The server also counts suppressions even if there is no next line.
func (b *Budget) Take(ctx context.Context, kind observability.DiagnosticKind) (int64, bool) {
	allowed := b.limit.Allow()
	observability.FromContext(ctx).ObserveDiagnostic(kind, allowed)
	if !allowed {
		b.suppressed.Add(1)
		return 0, false
	}
	return b.suppressed.Swap(0), true
}
