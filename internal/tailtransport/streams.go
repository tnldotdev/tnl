package tailtransport

import (
	"context"
	"errors"
	"net"
	"sync"
)

var errDraining = errors.New("tailtransport: draining")

type streamRegistry struct {
	mu        sync.Mutex
	draining  bool
	closed    bool
	opening   int
	streams   map[*trackedConn]struct{}
	changed   chan struct{}
	closeDone chan struct{}
}

func newStreamRegistry() *streamRegistry {
	return &streamRegistry{
		streams:   make(map[*trackedConn]struct{}),
		changed:   make(chan struct{}),
		closeDone: make(chan struct{}),
	}
}

func (r *streamRegistry) beginOpen() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.stateErrorLocked(); err != nil {
		return err
	}
	r.opening++
	return nil
}

func (r *streamRegistry) finishOpen(conn net.Conn, openErr error) (net.Conn, error) {
	r.mu.Lock()
	r.opening--
	stateErr := r.stateErrorLocked()
	if openErr == nil && stateErr == nil {
		tracked := r.trackLocked(conn)
		r.notifyLocked()
		r.mu.Unlock()
		return tracked, nil
	}
	r.notifyLocked()
	r.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
	if openErr != nil {
		return nil, openErr
	}
	return nil, stateErr
}

func (r *streamRegistry) track(conn net.Conn) (net.Conn, error) {
	r.mu.Lock()
	if err := r.stateErrorLocked(); err != nil {
		r.mu.Unlock()
		conn.Close()
		return nil, err
	}
	tracked := r.trackLocked(conn)
	r.mu.Unlock()
	return tracked, nil
}

func (r *streamRegistry) trackLocked(conn net.Conn) *trackedConn {
	tracked := &trackedConn{Conn: conn}
	tracked.release = func() {
		r.mu.Lock()
		delete(r.streams, tracked)
		r.notifyLocked()
		r.mu.Unlock()
	}
	r.streams[tracked] = struct{}{}
	return tracked
}

func (r *streamRegistry) drain(ctx context.Context) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return net.ErrClosed
	}
	r.draining = true
	for r.opening != 0 || len(r.streams) != 0 {
		changed := r.changed
		r.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			r.forceClose()
			return ctx.Err()
		}
		r.mu.Lock()
		if r.closed {
			r.mu.Unlock()
			return net.ErrClosed
		}
	}
	r.mu.Unlock()
	return nil
}

func (r *streamRegistry) close() {
	r.mu.Lock()
	if r.closed {
		done := r.closeDone
		r.mu.Unlock()
		<-done
		return
	}
	r.closed = true
	r.notifyLocked()
	streams := r.snapshotLocked()
	r.mu.Unlock()
	defer close(r.closeDone)
	for _, stream := range streams {
		stream.Close()
	}
}

func (r *streamRegistry) forceClose() {
	r.mu.Lock()
	streams := r.snapshotLocked()
	r.mu.Unlock()
	for _, stream := range streams {
		stream.Close()
	}
}

func (r *streamRegistry) snapshotLocked() []*trackedConn {
	streams := make([]*trackedConn, 0, len(r.streams))
	for stream := range r.streams {
		streams = append(streams, stream)
	}
	return streams
}

func (r *streamRegistry) stateErrorLocked() error {
	if r.closed {
		return net.ErrClosed
	}
	if r.draining {
		return errDraining
	}
	return nil
}

func (r *streamRegistry) notifyLocked() {
	close(r.changed)
	r.changed = make(chan struct{})
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
	conn, ok := c.Conn.(interface{ CloseRead() error })
	if !ok {
		return errors.ErrUnsupported
	}
	return conn.CloseRead()
}

func (c *trackedConn) CloseWrite() error {
	conn, ok := c.Conn.(interface{ CloseWrite() error })
	if !ok {
		return errors.ErrUnsupported
	}
	return conn.CloseWrite()
}
