package peer

import (
	"context"
	"sync"
)

// Carrier reserves the registered pair without starting its stream introduction
// deadline. open selects the stream initiator; the other endpoint accepts. the
// first packet operation establishes the stream. Close retires the registration
// and interrupts setup without closing the borrowed outer session.
func (p *StreamPair) Carrier(open bool) Carrier {
	return &registeredStreamCarrier{pair: p, open: open}
}

type registeredStreamCarrier struct {
	pair *StreamPair
	open bool
	once sync.Once
	live *SharedStreamCarrier
	err  error
}

func (c *registeredStreamCarrier) carrier(ctx context.Context) (*SharedStreamCarrier, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.once.Do(func() {
		if c.open {
			c.live, c.err = c.pair.Open(ctx)
		} else {
			c.live, c.err = c.pair.Accept(ctx)
		}
	})
	return c.live, c.err
}

func (c *registeredStreamCarrier) Send(ctx context.Context, frame []byte) error {
	live, err := c.carrier(ctx)
	if err != nil {
		return err
	}
	return live.Send(ctx, frame)
}

func (c *registeredStreamCarrier) Receive(ctx context.Context) ([]byte, error) {
	live, err := c.carrier(ctx)
	if err != nil {
		return nil, err
	}
	return live.Receive(ctx)
}

func (c *registeredStreamCarrier) Close() error { return c.pair.Close() }
