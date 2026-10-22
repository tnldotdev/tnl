package relay

import (
	"context"
	"errors"

	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type pendingForwarding struct {
	header    tunnelv1.InternalForwardingHeader
	ingress   *tunnel.Session
	current   func() bool
	attempted bool
}

// registerPending binds the decision to the same authenticated ingress session
// that opened the visitor, before any visitor byte can reach the publisher.
func (c *PublisherConnection) registerPending(h tunnelv1.InternalForwardingHeader, session *tunnel.Session, current func() bool) (func(), bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.draining || c.pending[h.VisitorConnectionID] != nil {
		return nil, false
	}
	p := &pendingForwarding{header: h, ingress: session, current: current}
	c.pending[h.VisitorConnectionID] = p
	return func() {
		c.mu.Lock()
		if c.pending[h.VisitorConnectionID] == p {
			delete(c.pending, h.VisitorConnectionID)
		}
		c.mu.Unlock()
	}, true
}

func admissionRejected(code tunnelv1.ErrorCode) tunnelv1.AdmissionResult {
	return tunnelv1.AdmissionResult{Type: tunnelv1.StreamRejected, Code: code}
}

func (c *PublisherConnection) promoteVisitor(ctx context.Context, h tunnelv1.AdmissionHeader) tunnelv1.AdmissionResult {
	c.mu.Lock()
	p := c.pending[h.VisitorConnectionID]
	if ctx.Err() != nil || c.closed || c.draining || p == nil || p.attempted || p.ingress == nil {
		c.mu.Unlock()
		return admissionRejected(tunnelv1.StaleConnectionAssignment)
	}
	want := p.header.Admission()
	want.Kind = tunnelv1.PublisherAdmissionStream
	want.RelayID = ""
	want.RelayRunID = ""
	want.RelayLeaseRevision = 0
	if h != want {
		c.mu.Unlock()
		return admissionRejected(tunnelv1.StaleConnectionAssignment)
	}
	p.attempted = true
	c.mu.Unlock()
	if p.current == nil || !p.current() {
		return admissionRejected(tunnelv1.StaleConnectionAssignment)
	}
	if err := p.ingress.PromoteVisitor(ctx, p.header.Admission()); err != nil {
		var protocolError *tunnel.ProtocolError
		if errors.As(err, &protocolError) {
			return admissionRejected(protocolError.Code)
		}
		return admissionRejected(tunnelv1.Unavailable)
	}
	return tunnelv1.AdmissionResult{Type: tunnelv1.StreamAccepted}
}
