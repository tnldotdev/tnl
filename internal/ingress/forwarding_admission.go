package ingress

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type forwardingAdmission struct {
	session   *tunnel.Session
	header    tunnelv1.AdmissionHeader
	attempted bool
}

// SetPromotionHandler is configured before serving visitors. the setter also
// supports runtime construction where Server needs Forwarder's lookup adapter.
func (f *Forwarder) SetPromotionHandler(handle func(context.Context, tunnelv1.AdmissionHeader) tunnelv1.AdmissionResult) {
	f.mu.Lock()
	f.promote = handle
	f.mu.Unlock()
}

func (f *Forwarder) removeAdmission(id string, value *forwardingAdmission) {
	f.mu.Lock()
	if f.pending[id] == value {
		delete(f.pending, id)
	}
	f.mu.Unlock()
}

func (f *Forwarder) promoteAdmission(ctx context.Context, session *tunnel.Session, h tunnelv1.AdmissionHeader) tunnelv1.AdmissionResult {
	f.mu.Lock()
	p := f.pending[h.VisitorConnectionID]
	handle := f.promote
	valid := !f.closed && ctx.Err() == nil && p != nil && p.session == session && p.header == h && !p.attempted && handle != nil
	if valid {
		p.attempted = true
	}
	f.mu.Unlock()
	if !valid {
		return tunnelv1.AdmissionResult{Type: tunnelv1.StreamRejected, Code: tunnelv1.StaleConnectionAssignment}
	}
	return handle(ctx, h)
}

type pendingForwardingConn struct {
	net.Conn
	once   sync.Once
	remove func()
}

func (c *pendingForwardingConn) Close() error { c.once.Do(c.remove); return c.Conn.Close() }
func (c *pendingForwardingConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return errors.ErrUnsupported
}
