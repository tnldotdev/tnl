package observability

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/trace"
)

const scope = "github.com/tnldotdev/tnl/internal/observability"
const ShutdownTimeout = 5 * time.Second

type ownerKey struct{}

func WithMetrics(ctx context.Context, m *Metrics) context.Context {
	return context.WithValue(ctx, ownerKey{}, m)
}

func FromContext(ctx context.Context) *Metrics {
	m, _ := ctx.Value(ownerKey{}).(*Metrics)
	return m
}

// Correlation returns only OTel trace identifiers for existing one-line logs.
// it does not format request input or copy arbitrary context values.
func Correlation(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return ""
	}
	return fmt.Sprintf(" trace_id=%s span_id=%s", sc.TraceID(), sc.SpanID())
}
