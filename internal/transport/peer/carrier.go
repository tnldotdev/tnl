// package peer owns packet delivery for one end-to-end QUIC session. role owners
// supply already-authorized carriers and the pair's short-lived introduction key.
// this package does not select a publisher, grant access, or dial a target.
package peer

import (
	"context"
	"net"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// Carrier moves bounded frames. Close must interrupt Send and Receive. a carrier
// belongs exclusively to its endpoint; it must not close a shared relay session.
type Carrier interface {
	Send(context.Context, []byte) error
	Receive(context.Context) ([]byte, error)
	Close() error
}

// DatagramCarrier owns a dedicated outer QUIC connection for the proof. shared
// relay sessions need a demultiplexed carrier with the same bounded interface.
type DatagramCarrier struct{ Conn *quic.Conn }

func (c DatagramCarrier) Send(ctx context.Context, b []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.Conn.SendDatagram(b)
}

func (c DatagramCarrier) Receive(ctx context.Context) ([]byte, error) {
	return c.Conn.ReceiveDatagram(ctx)
}

func (c DatagramCarrier) Close() error { return c.Conn.CloseWithError(0, "") }

// StreamCarrier preserves packet boundaries over a dedicated TLS/yamux stream.
// only the endpoint's writer calls Send; Receive runs independently.
type StreamCarrier struct {
	Conn net.Conn
	once sync.Once
	err  error
}

func (c *StreamCarrier) Send(ctx context.Context, b []byte) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(time.Second)
	}
	if err := c.Conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = c.Conn.SetWriteDeadline(time.Now())
		close(done)
	})
	defer func() {
		if !stop() {
			<-done
		}
	}()
	return tunnelv1.WritePeerFrame(c.Conn, b)
}

func (c *StreamCarrier) Receive(ctx context.Context) ([]byte, error) {
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	return tunnelv1.ReadPeerFrame(c.Conn)
}

func (c *StreamCarrier) Close() error {
	c.once.Do(func() { c.err = c.Conn.Close() })
	return c.err
}
