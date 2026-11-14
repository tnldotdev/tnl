package ingress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type serviceSelectionControl struct {
	*publicServiceControlFixture
	runs      []ingressv1.PublicServiceVisitorAdmission
	claims    []ingressv1.PublicServiceVisitorClaim
	deadlines []time.Time
	actions   []string
	live      map[string]ingressv1.PublicServiceVisitorAdmission
	before    func(context.Context, *ingressv1.PublicServiceVisitorAdmission) error
	close     func(context.Context, ingressv1.PublicServiceVisitorLookup) error
}

func (c *serviceSelectionControl) AdmitPublicServiceVisitor(ctx context.Context, id string, claim ingressv1.PublicServiceVisitorClaim) (ingressv1.PublicServiceVisitorAdmission, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	claim.ExcludedRuns = append([]ingressv1.ServiceRunReference(nil), claim.ExcludedRuns...)
	c.claims = append(c.claims, claim)
	deadline, _ := ctx.Deadline()
	c.deadlines = append(c.deadlines, deadline)
	c.actions = append(c.actions, "admit "+claim.VisitorConnectionId)
	if id != "ingress-a" || claim.IngressLeaseRevision != 1 || claim.Hostname == nil || *claim.Hostname != "route.example" ||
		claim.ObservedSourceIp != "192.0.2.4" || claim.DestinationPort != 443 || len(claim.ExcludedRuns) > 7 {
		return ingressv1.PublicServiceVisitorAdmission{}, ErrServiceAdmission
	}
	for _, run := range c.runs {
		if len(run.ConnectedRelays) == 0 {
			continue
		}
		excluded := false
		for _, ref := range claim.ExcludedRuns {
			if ref.ServiceId == run.ServiceId && ref.ServiceRunId == run.ServiceRunId && ref.RunNumber == run.RunNumber {
				excluded = true
			}
		}
		if excluded {
			continue
		}
		run.VisitorConnectionId = claim.VisitorConnectionId
		if c.before != nil {
			if err := c.before(ctx, &run); err != nil {
				return ingressv1.PublicServiceVisitorAdmission{}, err
			}
		}
		c.live[claim.VisitorConnectionId] = run
		return run, nil
	}
	return ingressv1.PublicServiceVisitorAdmission{}, ErrServiceAdmission
}

func (c *serviceSelectionControl) ClosePublicServiceVisitor(ctx context.Context, id string, lookup ingressv1.PublicServiceVisitorLookup) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.actions = append(c.actions, "close "+lookup.VisitorConnectionId)
	if c.close != nil {
		if err := c.close(ctx, lookup); err != nil {
			return err
		}
	}
	delete(c.live, lookup.VisitorConnectionId)
	c.closed++
	return nil
}

type serviceSelectionForwarder struct {
	mu       sync.Mutex
	openings map[string]serviceRelayOpening
	observed []tunnelv1.ServiceForwardingHeader
}

func (f *serviceSelectionForwarder) OpenPrivate(ctx context.Context, relay ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader) (net.Conn, error) {
	f.mu.Lock()
	f.observed = append(f.observed, header)
	open := f.openings[header.ServiceRunID]
	f.mu.Unlock()
	if header.Validate() != nil || header.PublicService == nil || header.PublicService.DestinationPort != 443 ||
		header.PublisherConnectionID != relay.PublisherConnectionId || header.ConnectionSlot != uint8(relay.ConnectionSlot) {
		return nil, ErrServiceAdmission
	}
	if open == nil {
		return nil, errors.New("unselected service run reached the relay")
	}
	return open(ctx, header)
}

func serviceSelectionConfig(t *testing.T, count int, anonymous bool) (Config, *serviceSelectionControl, *serviceSelectionForwarder) {
	t.Helper()
	config, base, _, _ := publicServiceTestConfig(t)
	control := &serviceSelectionControl{publicServiceControlFixture: base, live: make(map[string]ingressv1.PublicServiceVisitorAdmission)}
	for number := range count {
		relay := base.relays[0]
		relay.PublisherConnectionId = publicServiceTestID(t, "pc_")
		control.runs = append(control.runs, ingressv1.PublicServiceVisitorAdmission{
			ServiceId: base.service, ServiceRunId: publicServiceTestID(t, "srun_"), RunNumber: int64(number + 1),
			ExpiresAt: time.Now().Add(time.Minute), ConnectedRelays: []ingressv1.ServiceRelay{relay}, Traffic: base.traffic, Anonymous: anonymous,
		})
	}
	forwarder := &serviceSelectionForwarder{openings: make(map[string]serviceRelayOpening)}
	config.Control, config.Forwarder = control, forwarder
	config.RequireProxyHeader = true
	config.TrustedProxyPeers = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	return config, control, forwarder
}

func serviceSelectionServer(t *testing.T, config Config) *Server {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(listener, config)
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return server
}

func rejectServiceSelection(t *testing.T, ctx context.Context, server *Server) error {
	t.Helper()
	connection, visitor := net.Pipe()
	defer visitor.Close()
	return server.AcceptPublic(ctx, connection, netip.MustParseAddrPort("192.0.2.4:42000"), netip.MustParseAddrPort("203.0.113.10:443"), "route.example", nil)
}
