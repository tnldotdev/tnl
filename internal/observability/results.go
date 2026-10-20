package observability

import (
	"context"
	"errors"
	"net"

	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/failure"
	"go.opentelemetry.io/otel/trace"
)

// ErrorOutcome classifies causes without formatting them. callers retain the
// original error; this function never wraps or replaces it.
func ErrorOutcome(err error) Outcome {
	if err == nil {
		return Success
	}
	if errors.Is(err, context.Canceled) {
		return Canceled
	}
	var network net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &network) && network.Timeout() {
		return Timeout
	}
	if _, def, ok := failure.Describe(err); ok {
		switch def.Class {
		case failure.Forbidden, failure.Unauthenticated:
			return Denied
		case failure.Invalid, failure.Conflict, failure.NotFound, failure.Stale, failure.RateLimited:
			return Rejected
		}
	}
	return Error
}

// FailureCode exports only codes owned by the failure or diagnostic catalog.
func FailureCode(err error) string {
	if err == nil {
		return ""
	}
	if reason, ok := failure.ReasonOf(err); ok {
		return string(reason)
	}
	if code, ok := diagnostic.CodeOf(err); ok {
		return string(code)
	}
	return string(failure.Unexpected)
}

func finishError(span trace.Span, err error) {
	finishSpan(span, string(ErrorOutcome(err)))
	if err != nil {
		span.SetAttributes(ErrorType.String(FailureCode(err)))
	}
}
