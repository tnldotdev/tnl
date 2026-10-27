package muxsession

import (
	"bytes"
	"context"
)

// quic-go's datagram enqueue blocks when its transport queue fills and has no
// context parameter. this session-owned worker holds at most one submitted
// packet outside that queue. borrowers can cancel and join without closing a
// shared session or leaving a goroutine per canceled packet. the session closes
// QUIC before joining this worker, which releases any blocked library enqueue.
type quicDatagramSender struct {
	ctx      context.Context
	requests chan quicDatagramRequest
	done     chan struct{}
}

type quicDatagramRequest struct {
	ctx    context.Context
	packet []byte
	result chan error
}

func newQUICDatagramSender(ctx context.Context, send func([]byte) error) *quicDatagramSender {
	s := &quicDatagramSender{ctx: ctx, requests: make(chan quicDatagramRequest), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		for {
			select {
			case <-ctx.Done():
				return
			case request := <-s.requests:
				if err := context.Cause(ctx); err != nil {
					request.result <- err
					return
				}
				if err := context.Cause(request.ctx); err != nil {
					request.result <- err
					continue
				}
				request.result <- send(request.packet)
			}
		}
	}()
	return s
}

func (s *quicDatagramSender) send(ctx context.Context, packet []byte) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if err := context.Cause(s.ctx); err != nil {
		return normalizeQUICError(err)
	}
	// the caller can reuse its bytes after cancellation even while quic-go
	// still holds the single submitted request on the session's worker.
	request := quicDatagramRequest{ctx: ctx, packet: bytes.Clone(packet), result: make(chan error, 1)}
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-s.ctx.Done():
		return normalizeQUICError(context.Cause(s.ctx))
	case s.requests <- request:
	}
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-s.ctx.Done():
		return normalizeQUICError(context.Cause(s.ctx))
	case err := <-request.result:
		if cause := context.Cause(ctx); cause != nil {
			return cause
		}
		if cause := context.Cause(s.ctx); cause != nil {
			return normalizeQUICError(cause)
		}
		return normalizeQUICError(err)
	}
}
