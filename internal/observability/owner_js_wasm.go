package observability

import (
	"context"

	"github.com/tnldotdev/tnl/internal/failure"
	"go.opentelemetry.io/otel/trace"
)

// there is no process telemetry owner in the portable SDK. the build constant
// lets callers omit local measurements without removing wire trace context.
const processTelemetry = false

type processMetrics struct{}

func (processMetrics) tracer() trace.Tracer { return nil }

func OperationalFailure(context.Context, failure.Operation, failure.Reason, string, error) {}
