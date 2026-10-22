package relay

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/tnldotdev/tnl/internal/transport/tunnel"
)

var ErrDraining = errors.New("relay: draining")

// streamLifetime owns pending opens and admitted streams for either kind of
// publisher connection. it must stay pointer-owned through drain and close.
type streamLifetime struct {
	session *tunnel.Session

	mu       sync.Mutex
	draining bool
	closed   bool
	opening  int
	streams  map[*trackedConn]struct{}
	changed  chan struct{}

	closeOnce sync.Once
	closeErr  error
}

func newStreamLifetime(session *tunnel.Session) *streamLifetime {
	return &streamLifetime{session: session, streams: make(map[*trackedConn]struct{}), changed: make(chan struct{})}
}

func (c *streamLifetime) beginOpen() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.stateErrorLocked(); err != nil {
		return err
	}
	c.opening++
	return nil
}

func (c *streamLifetime) finishOpen(connection net.Conn, openErr error) (net.Conn, error) {
	c.mu.Lock()
	stateErr := c.stateErrorLocked()
	if openErr == nil && stateErr == nil {
		c.opening--
		tracked := &trackedConn{Conn: connection}
		tracked.release = func() {
			c.mu.Lock()
			delete(c.streams, tracked)
			c.notifyLocked()
			c.mu.Unlock()
		}
		c.streams[tracked] = struct{}{}
		c.notifyLocked()
		c.mu.Unlock()
		return tracked, nil
	}
	c.mu.Unlock()
	if connection != nil {
		_ = connection.Close()
	}
	// retain the pending reservation until a rejected open's stream is closed.
	// drain and close must not finish while that cleanup is still in flight.
	c.mu.Lock()
	c.opening--
	c.notifyLocked()
	c.mu.Unlock()
	if openErr != nil {
		return nil, openErr
	}
	return nil, stateErr
}

func (c *streamLifetime) Drain(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	c.draining = true
	for c.opening != 0 || len(c.streams) != 0 {
		changed := c.changed
		c.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			_ = c.Close()
			return context.Cause(ctx)
		}
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return net.ErrClosed
		}
	}
	c.mu.Unlock()
	return nil
}

func (c *streamLifetime) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.draining = true
		streams := c.snapshotLocked()
		c.notifyLocked()
		c.mu.Unlock()
		for _, stream := range streams {
			_ = stream.Close()
		}
		c.closeErr = c.session.Close()
		c.mu.Lock()
		for c.opening != 0 || len(c.streams) != 0 {
			changed := c.changed
			c.mu.Unlock()
			<-changed
			c.mu.Lock()
		}
		c.mu.Unlock()
	})
	return c.closeErr
}

func (c *streamLifetime) stateErrorLocked() error {
	if c.closed {
		return net.ErrClosed
	}
	if c.draining {
		return ErrDraining
	}
	return nil
}

func (c *streamLifetime) snapshotLocked() []*trackedConn {
	result := make([]*trackedConn, 0, len(c.streams))
	for stream := range c.streams {
		result = append(result, stream)
	}
	return result
}

func (c *streamLifetime) notifyLocked() {
	close(c.changed)
	c.changed = make(chan struct{})
}

type trackedConn struct {
	net.Conn
	closeOnce sync.Once
	closeErr  error
	release   func()
}

func (c *trackedConn) Close() error {
	c.closeOnce.Do(func() {
		defer c.release()
		c.closeErr = c.Conn.Close()
	})
	return c.closeErr
}

func (c *trackedConn) CloseRead() error {
	connection, ok := c.Conn.(interface{ CloseRead() error })
	if !ok {
		return errors.ErrUnsupported
	}
	return connection.CloseRead()
}

func (c *trackedConn) CloseWrite() error {
	connection, ok := c.Conn.(interface{ CloseWrite() error })
	if !ok {
		return errors.ErrUnsupported
	}
	return connection.CloseWrite()
}
