package relay

import (
	"context"
	"time"
)

type OperationObserver interface {
	ObserveOperation(operation string, err error, elapsed time.Duration)
}

func startOperation(ctx context.Context, observer OperationObserver, operation string) func(error) {
	if observer == nil {
		return func(error) {}
	}
	started := time.Now()
	return func(err error) {
		if err != nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		observer.ObserveOperation(operation, err, time.Since(started))
	}
}
