package stream

import (
	"context"
	"errors"
	"net"
	"sync"
)

// both access paths own the same bounded loopback accept/join lifecycle. the
// selected path owns authentication and never replays one accepted connection.
func serveLoopback(ctx context.Context, listener net.Listener, limit int, ready func() error, forward func(context.Context, net.Conn)) error {
	if limit == 0 {
		limit = 64
	}
	workersCtx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	stop := context.AfterFunc(workersCtx, func() { _ = listener.Close() })
	defer func() { cancel(); stop(); _ = listener.Close(); workers.Wait() }()
	if ready != nil {
		if err := ready(); err != nil {
			return err
		}
	}
	capacity := make(chan struct{}, limit)
	for {
		local, err := listener.Accept()
		if err != nil {
			if cause := context.Cause(ctx); IsMetadataReload(cause) {
				return cause
			}
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case capacity <- struct{}{}:
		default:
			_ = local.Close()
			continue
		}
		workers.Go(func() {
			defer func() { <-capacity; _ = local.Close() }()
			forward(workersCtx, local)
		})
	}
}
