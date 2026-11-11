package muxsession

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

// NonQUICPacketConn borrows the non-QUIC side of a transport's existing socket.
// the caller must create exactly one view per transport. closing the child or
// changing its read deadline never closes or changes the physical socket.
func NonQUICPacketConn(parent context.Context, transport *quic.Transport, local net.Addr) net.PacketConn {
	return newNonQUICPacketConn(parent, local, transport.ReadNonQUICPacket, transport.WriteTo)
}

func newNonQUICPacketConn(parent context.Context, local net.Addr,
	read func(context.Context, []byte) (int, net.Addr, error), write func([]byte, net.Addr) (int, error),
) *nonQUICPacketConn {
	ctx, cancel := context.WithCancel(parent)
	return &nonQUICPacketConn{local: local, ctx: ctx, cancel: cancel, read: read, write: write}
}

type nonQUICPacketConn struct {
	local     net.Addr
	ctx       context.Context
	cancel    context.CancelFunc
	read      func(context.Context, []byte) (int, net.Addr, error)
	write     func([]byte, net.Addr) (int, error)
	readMu    sync.Mutex
	mu        sync.Mutex
	deadline  time.Time
	interrupt context.CancelFunc
}

func (c *nonQUICPacketConn) LocalAddr() net.Addr { return c.local }
func (c *nonQUICPacketConn) Close() error        { c.cancel(); return nil }

func (c *nonQUICPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	// quic-go initializes non-QUIC dispatch on the first read. serialize readers
	// so initialization and deadline cancellation have exactly one owner.
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		c.mu.Lock()
		var ctx context.Context
		var cancel context.CancelFunc
		if c.deadline.IsZero() {
			ctx, cancel = context.WithCancel(c.ctx)
		} else {
			ctx, cancel = context.WithDeadline(c.ctx, c.deadline)
		}
		c.interrupt = cancel
		c.mu.Unlock()
		n, addr, err := c.read(ctx, b)
		cancel()
		c.mu.Lock()
		c.interrupt = nil
		expired := !c.deadline.IsZero() && !time.Now().Before(c.deadline)
		c.mu.Unlock()
		if c.ctx.Err() != nil {
			return 0, nil, net.ErrClosed
		}
		if expired {
			return 0, nil, os.ErrDeadlineExceeded
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			continue
		}
		return n, addr, err
	}
}

func (c *nonQUICPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if c.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	return c.write(b, addr)
}

func (c *nonQUICPacketConn) SetReadDeadline(at time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = at
	if c.interrupt != nil {
		c.interrupt()
	}
	return nil
}

// a child cannot change the shared socket's write deadline. a nonzero deadline
// is explicitly unsupported rather than silently interrupting QUIC connections.
func (c *nonQUICPacketConn) SetWriteDeadline(at time.Time) error {
	if !at.IsZero() {
		return errors.ErrUnsupported
	}
	return nil
}

func (c *nonQUICPacketConn) SetDeadline(at time.Time) error {
	return errors.Join(c.SetReadDeadline(at), c.SetWriteDeadline(at))
}

// NonQUICPackets returns the listener's single borrowed packet view. subsequent
// calls return a closed view, including after the first child's context ends.
// source-pinned listeners return reply addresses with a UDPAddr method; writing
// back to that same address preserves the received local-IP/interface metadata.
func (l *QUICListener) NonQUICPackets(ctx context.Context) net.PacketConn {
	l.nonQUICMu.Lock()
	defer l.nonQUICMu.Unlock()
	if l.nonQUIC != nil {
		closed, cancel := context.WithCancel(ctx)
		cancel()
		return newNonQUICPacketConn(closed, l.Addr(), func(context.Context, []byte) (int, net.Addr, error) {
			return 0, nil, net.ErrClosed
		}, func([]byte, net.Addr) (int, error) { return 0, net.ErrClosed })
	}
	if l.sources != nil {
		l.nonQUIC = l.sources.nonQUICPackets(ctx)
	} else {
		l.nonQUIC = NonQUICPacketConn(ctx, l.transport, l.packetConn.LocalAddr())
	}
	return l.nonQUIC
}
