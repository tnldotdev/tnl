package ingress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestDirectAdmissionExpiryAtUse(t *testing.T) {
	now := time.Now()
	for _, expiry := range []string{"run", "relay"} {
		t.Run(expiry, func(t *testing.T) {
			_, c, _, _ := directTestSetup(t)
			p := ingressv1.DirectServiceVisitorAdmission{ServiceId: c.service, ServiceRunId: c.run, RunNumber: 1, ExpiresAt: now.Add(time.Minute), ConnectedRelays: c.relays}
			if expiry == "run" {
				p.ExpiresAt = now
			} else {
				p.ConnectedRelays[0].LeaseExpiresAt = now
			}
			if err := validateDirectAdmission(p, now.Add(-time.Nanosecond)); err != nil {
				t.Fatalf("live claim rejected: %v", err)
			}
			if err := validateDirectAdmission(p, now); !errors.Is(err, ErrServiceAdmission) {
				t.Fatalf("claim accepted at expiry: %v", err)
			}
		})
	}
}

type changedDirectControl struct {
	*directControlFixture
	change func(*ingressv1.DirectServiceVisitorAdmission)
}

func (c changedDirectControl) AdmitDirectServiceVisitor(ctx context.Context, id string, claim ingressv1.DirectServiceVisitorClaim) (ingressv1.DirectServiceVisitorAdmission, error) {
	admitted, err := c.directControlFixture.AdmitDirectServiceVisitor(ctx, id, claim)
	c.change(&admitted)
	return admitted, err
}

type rejectedDirectForwarder struct{ calls int }

func (f *rejectedDirectForwarder) OpenPrivate(context.Context, ingressv1.ServiceRelay, tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
	f.calls++
	return nil, ErrServiceAdmission
}

func TestDirectVisitorRejectsExpiredOrMalformedClaim(t *testing.T) {
	for name, change := range map[string]func(*ingressv1.DirectServiceVisitorAdmission){
		"expired claim": func(p *ingressv1.DirectServiceVisitorAdmission) { p.ExpiresAt = time.Now().Add(-time.Second) },
		"expired relay with live sibling": func(p *ingressv1.DirectServiceVisitorAdmission) {
			p.ConnectedRelays[0].LeaseExpiresAt = time.Now().Add(-time.Second)
		},
		"missing service":    func(p *ingressv1.DirectServiceVisitorAdmission) { p.ServiceId = "" },
		"missing run":        func(p *ingressv1.DirectServiceVisitorAdmission) { p.ServiceRunId = "" },
		"missing run number": func(p *ingressv1.DirectServiceVisitorAdmission) { p.RunNumber = 0 },
		"missing relays":     func(p *ingressv1.DirectServiceVisitorAdmission) { p.ConnectedRelays = nil },
		"invalid slot":       func(p *ingressv1.DirectServiceVisitorAdmission) { p.ConnectedRelays[0].ConnectionSlot = 2 },
		"duplicate slot":     func(p *ingressv1.DirectServiceVisitorAdmission) { p.ConnectedRelays[1].ConnectionSlot = 0 },
		"duplicate relay service": func(p *ingressv1.DirectServiceVisitorAdmission) {
			p.ConnectedRelays[1].RelayServiceId = p.ConnectedRelays[0].RelayServiceId
		},
		"missing relay expiry": func(p *ingressv1.DirectServiceVisitorAdmission) { p.ConnectedRelays[0].LeaseExpiresAt = time.Time{} },
		"missing assignment": func(p *ingressv1.DirectServiceVisitorAdmission) {
			p.ConnectedRelays[0].ConnectionAssignmentRevision = 0
		},
		"missing relay process": func(p *ingressv1.DirectServiceVisitorAdmission) { p.ConnectedRelays[0].RelayRunId = "" },
		"missing relay lease":   func(p *ingressv1.DirectServiceVisitorAdmission) { p.ConnectedRelays[0].RelayLeaseRevision = 0 },
		"wrong visitor":         func(p *ingressv1.DirectServiceVisitorAdmission) { p.VisitorConnectionId = "vc_0123456789ABCDEFGHIJKL" },
	} {
		t.Run(name, func(t *testing.T) {
			p, c, _, _ := directTestSetup(t)
			forwarder := new(rejectedDirectForwarder)
			p.config.Control, p.config.Forwarder = changedDirectControl{c, change}, forwarder
			connection, visitor := net.Pipe()
			defer connection.Close()
			defer visitor.Close()
			err := p.AcceptDirect(t.Context(), connection, netip.MustParseAddrPort("192.0.2.4:42000"), netip.MustParseAddrPort("203.0.113.8:20000"))
			if !errors.Is(err, ErrServiceAdmission) || forwarder.calls != 0 || c.closed != 1 || p.Load() != 0 {
				t.Fatalf("invalid admission: err=%v forwarded=%d closed=%d sessions=%d", err, forwarder.calls, c.closed, p.Load())
			}
		})
	}
}
