package peer

import (
	"context"
	"sync"
)

// RetainCarrierReplay keeps one bounded receive history across replacements of
// the underlying carrier. that carrier must authenticate frames first. this
// filter prevents a replay on a new outer session from reaching a retained
// TLS/yamux stream, whose per-registration history would reject the stream.
func RetainCarrierReplay(carrier Carrier) Carrier {
	return &replayCarrier{Carrier: carrier}
}

type replayCarrier struct {
	Carrier
	mu     sync.Mutex
	replay replayWindow
}

var _ Carrier = (*replayCarrier)(nil)

func (c *replayCarrier) Receive(ctx context.Context) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		frame, err := c.Carrier.Receive(ctx)
		if err != nil {
			return nil, err
		}
		if c.replay.accept(frame) {
			return frame, nil
		}
	}
}
