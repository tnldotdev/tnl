package ingress

import (
	"context"
	"net"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/transport/streamcopy"
)

// copyLiveNativeVisitor remains under its locally bound permission, allocation,
// and infrastructure lifetimes. cancellation closes and joins both directions
// before their ordinary stream capacity is released; it performs no control I/O.
func copyLiveNativeVisitor(ctx context.Context, visitor net.Conn, backend net.Conn) (retErr error) {
	ctx, finishForward := observability.Start(ctx, "ingress.forward_connector_visitor")
	defer func() { finishForward(retErr) }()
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = visitor.Close(); _ = backend.Close(); close(closed) })
	defer func() {
		if !stop() {
			<-closed
		}
	}()
	_, err := streamcopy.Copy(visitor, backend)
	return err
}

func privateMinTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}
