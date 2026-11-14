package ingress

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
)

// keep backend ownership through the final close, including a copy failure racing
// authorization shutdown. every closer receives the same independent close cause.
func (p *PublicServices) observeBackend(ctx context.Context, connection net.Conn) net.Conn {
	p.mu.Lock()
	p.streams++
	p.reportStreamsLocked()
	p.mu.Unlock()
	closeBackend := sync.OnceValue(func() error {
		started := time.Now()
		err := connection.Close()
		p.mu.Lock()
		p.streams--
		p.reportStreamsLocked()
		p.mu.Unlock()
		if p.config.Observer != nil {
			p.config.Observer.ObserveOperationContext(ctx, observability.OpIngressBackendCleanup, err, time.Since(started))
		}
		return err
	})
	return &serviceBackendConn{Conn: connection, close: closeBackend}
}

func (p *PublicServices) reportStreamsLocked() {
	if p.config.Metrics != nil {
		p.config.Metrics.SetIngressStreams(p.streams)
	}
}

type serviceBackendConn struct {
	net.Conn
	close func() error
}

func (c *serviceBackendConn) Close() error { return c.close() }

func (c *serviceBackendConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return errors.ErrUnsupported
}
