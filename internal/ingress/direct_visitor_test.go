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

func TestDirectProjectionExpiryAtUse(t *testing.T) {
	now := time.Date(2026, time.October, 29, 0, 0, 0, 0, time.UTC)
	for _, expiry := range []string{"run", "relay"} {
		t.Run(expiry, func(t *testing.T) {
			projection := serviceRoutingEntry(t, now)
			if expiry == "run" {
				projection.ExpiresAt = now
			} else {
				(*projection.ConnectedRelays)[0].LeaseExpiresAt = now
			}
			if err := validatePrivateProjection(projection); err != nil {
				t.Fatalf("expired projection has invalid shape: %v", err)
			}
			if err := validateDirectProjection(projection, now.Add(-time.Nanosecond)); err != nil {
				t.Fatalf("live direct projection rejected: %v", err)
			}
			if err := validateDirectProjection(projection, now); !errors.Is(err, ErrPrivateRoutingStale) {
				t.Fatalf("direct projection accepted at expiry: %v", err)
			}
			var table ServiceRoutingTable
			if err := table.ApplySnapshot(ingressv1.ServiceSnapshot{Revision: 1, Entries: []ingressv1.ServiceProjection{projection}}); err != nil {
				t.Fatal(err)
			}
			if _, ok := table.Lookup(projection.ServiceId, *projection.ServiceRunId, *projection.RunNumber, now); ok {
				t.Fatal("lookup accepted projection at expiry")
			}
		})
	}
}

type directProjectionControl struct {
	directControlFixture
	change func(*ingressv1.DirectServiceVisitorAdmission)
	closed int
}

func (c *directProjectionControl) AdmitDirectServiceVisitor(ctx context.Context, id string, claim ingressv1.DirectServiceVisitorClaim) (ingressv1.DirectServiceVisitorAdmission, error) {
	admitted, err := c.directControlFixture.AdmitDirectServiceVisitor(ctx, id, claim)
	c.change(&admitted)
	return admitted, err
}

func (c *directProjectionControl) CloseDirectServiceVisitor(context.Context, string, ingressv1.DirectServiceVisitorLookup) error {
	c.closed++
	return nil
}

type directProjectionForwarder struct{ calls int }

func (f *directProjectionForwarder) OpenPrivate(context.Context, ingressv1.ServiceRelay, tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
	f.calls++
	return nil, ErrServiceAdmission
}

func TestDirectVisitorRejectsExpiredOrMalformedClaim(t *testing.T) {
	for name, change := range map[string]func(*ingressv1.DirectServiceVisitorAdmission){
		"expired claim": func(p *ingressv1.DirectServiceVisitorAdmission) { p.ExpiresAt = time.Now().Add(-time.Second) },
		"expired relay with live sibling": func(p *ingressv1.DirectServiceVisitorAdmission) {
			p.ConnectedRelays[0].LeaseExpiresAt = time.Now().Add(-time.Second)
		},
		"malformed relay": func(p *ingressv1.DirectServiceVisitorAdmission) { p.ConnectedRelays[0].ConnectionSlot = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			p, control, _, _, _, _ := privateTestSetup(t)
			defer p.Close()
			claims := &directProjectionControl{directControlFixture: directControlFixture{control}, change: change}
			forwarder := new(directProjectionForwarder)
			p.config.DirectControl, p.config.Forwarder = claims, forwarder
			connection, visitor := net.Pipe()
			defer connection.Close()
			defer visitor.Close()
			err := p.AcceptDirect(t.Context(), connection, netip.MustParseAddrPort("192.0.2.4:42000"), netip.MustParseAddrPort("203.0.113.8:20000"))
			if !errors.Is(err, ErrServiceAdmission) || forwarder.calls != 0 || claims.closed != 1 || p.Load() != 0 {
				t.Fatalf("invalid direct admission: err=%v forwarded=%d closed=%d sessions=%d", err, forwarder.calls, claims.closed, p.Load())
			}
		})
	}
}
