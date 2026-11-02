package peer

import (
	"context"
	"net"
	"sync"
)

// Carrier reserves the registered pair without starting its stream introduction
// deadline. open selects the stream initiator; the other endpoint accepts. the
// first send establishes an initiated stream. reads stay passive until then,
// so preparation cannot race an introduction ahead of the remote registration.
// Close retires the registration
// and interrupts setup without closing the borrowed outer session.
func (p *StreamPair) Carrier(open bool) Carrier {
	return &registeredStreamCarrier{pair: p, open: open, ready: make(chan struct{})}
}

type registeredStreamCarrier struct {
	pair  *StreamPair
	open  bool
	once  sync.Once
	live  *SharedStreamCarrier
	err   error
	ready chan struct{}
}

func (c *registeredStreamCarrier) carrier(ctx context.Context, send bool) (*SharedStreamCarrier, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !c.open || send {
		c.once.Do(func() {
			defer close(c.ready)
			if c.open {
				c.live, c.err = c.pair.Open(ctx)
			} else {
				c.live, c.err = c.pair.Accept(ctx)
			}
		})
	}
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case <-c.pair.done:
		return nil, net.ErrClosed
	case <-c.ready:
	}
	return c.live, c.err
}

func (c *registeredStreamCarrier) Send(ctx context.Context, frame []byte) error {
	live, err := c.carrier(ctx, true)
	if err != nil {
		return err
	}
	return live.Send(ctx, frame)
}

func (c *registeredStreamCarrier) Receive(ctx context.Context) ([]byte, error) {
	live, err := c.carrier(ctx, false)
	if err != nil {
		return nil, err
	}
	return live.Receive(ctx)
}

func (c *registeredStreamCarrier) Close() error { return c.pair.Close() }
