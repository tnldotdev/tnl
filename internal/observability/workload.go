package observability

import (
	"context"

	"go.opentelemetry.io/otel/trace"
)

// WorkloadExecution attaches only control-authenticated execution references.
// these fields are trace-only, never metric dimensions or visitor baggage.
func WorkloadExecution(ctx context.Context, session, run, attempt, check string) {
	trace.SpanFromContext(ctx).SetAttributes(WorkloadSessionID.String(session), WorkloadRunID.String(run), WorkloadRunAttempt.String(attempt), WorkloadCheckRunID.String(check))
}
