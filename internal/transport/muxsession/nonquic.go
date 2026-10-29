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

// NonQUICPacketConn gives STUN/ICE the non-QUIC side of a transport's existing
// socket. one dispatcher owns this view. closing it interrupts its reads without
// closing accepted QUIC sessions or changing the shared socket's deadlines.
func NonQUICPacketConn(parent context.Context, transport *quic.Transport, local net.Addr) net.PacketConn {
	ctx, cancel := context.WithCancel(parent)
	return &nonQUICPacketConn{transport: transport, local: local, ctx: ctx, cancel: cancel}
}

type nonQUICPacketConn struct {
	transport *quic.Transport
	local     net.Addr
	ctx       context.Context
	cancel    context.CancelFunc
	readMu    sync.Mutex
	mu        sync.Mutex
	deadline  time.Time
	interrupt context.CancelFunc
}

func (c *nonQUICPacketConn) LocalAddr() net.Addr { return c.local }
func (c *nonQUICPacketConn) Close() error        { c.cancel(); return nil }

func (c *nonQUICPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	// quic-go initializes its non-QUIC dispatch channel on the first read.
	// serialize callers so initialization and cancellation have one owner.
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
		n, addr, err := c.transport.ReadNonQUICPacket(ctx, b)
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
	return c.transport.WriteTo(b, addr)
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

// a child view cannot change the physical socket's write deadline: that would
// interrupt unrelated QUIC sessions. callers must close their own child on abort.
func (c *nonQUICPacketConn) SetWriteDeadline(time.Time) error { return errors.ErrUnsupported }
func (c *nonQUICPacketConn) SetDeadline(at time.Time) error {
	return errors.Join(c.SetReadDeadline(at), c.SetWriteDeadline(at))
}

func (l *QUICListener) NonQUICPackets(ctx context.Context) net.PacketConn {
	return NonQUICPacketConn(ctx, l.transport, l.packetConn.LocalAddr())
}
