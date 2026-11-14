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
func (p *Server) observeBackend(ctx context.Context, connection net.Conn) (net.Conn, error) {
	var owned *ownedConn
	closeBackend := sync.OnceValue(func() error {
		started := time.Now()
		err := connection.Close()
		p.mu.Lock()
		delete(p.backends, owned)
		p.reportStreamsLocked()
		p.mu.Unlock()
		if p.config.Observer != nil {
			p.config.Observer.ObserveOperationContext(ctx, observability.OpIngressBackendCleanup, err, time.Since(started))
		}
		return err
	})
	owned = &ownedConn{Conn: connection, close: closeBackend}
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		return nil, errors.Join(errBackendTrackingClosed, connection.Close())
	}
	p.backends[owned] = struct{}{}
	p.reportStreamsLocked()
	p.mu.Unlock()
	return owned, nil
}

func (p *Server) reportStreamsLocked() {
	if p.config.Metrics != nil {
		p.config.Metrics.SetIngressStreams(len(p.backends))
	}
}

type ownedConn struct {
	net.Conn
	close func() error
}

func onceCloseConn(connection net.Conn) net.Conn {
	return &ownedConn{Conn: connection, close: sync.OnceValue(connection.Close)}
}

func (c *ownedConn) Close() error { return c.close() }

func (c *ownedConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return errors.ErrUnsupported
}

func (c *ownedConn) CloseRead() error {
	if closer, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return closer.CloseRead()
	}
	return errors.ErrUnsupported
}
