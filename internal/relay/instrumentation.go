package relay

import (
	"context"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
)

type OperationObserver interface {
	ObserveOperationContext(context.Context, observability.ServerOperation, error, time.Duration)
}

type ForwardingObserver interface {
	OperationObserver
	ObserveRelayTransfer(string, int64, int64, error)
}

func startOperation(ctx context.Context, observer OperationObserver, operation observability.ServerOperation) func(error) {
	if observer == nil {
		return func(error) {}
	}
	started := time.Now()
	return func(err error) {
		if err != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		observer.ObserveOperationContext(ctx, operation, err, time.Since(started))
	}
}
