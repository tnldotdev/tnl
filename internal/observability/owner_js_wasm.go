package observability

import (
	"context"

	"github.com/tnldotdev/tnl/internal/failure"
	"go.opentelemetry.io/otel/trace"
)

// there is no process telemetry owner in the portable SDK.
type processMetrics struct{}

func (processMetrics) tracer() trace.Tracer { return nil }

func OperationalFailure(context.Context, failure.Operation, failure.Reason, string, error) {}
