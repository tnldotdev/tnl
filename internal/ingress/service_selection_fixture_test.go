package ingress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
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
	native    bool
}

func (c *serviceSelectionControl) ReadIngressServices(ctx context.Context, id string, lease ingressv1.IngressLeaseIdentity) (ingressv1.IngressServices, error) {
	if c.native {
		return c.publicServiceControlFixture.ReadIngressServices(ctx, id, lease)
	}
	now := time.Now()
	snapshot := ingressv1.IngressServices{ObservedAt: now, ValidUntil: now.Add(visitortoken.PolicyLifetime)}
	for _, candidate := range c.runs {
		run := ingressv1.IngressServiceRun{ServiceId: candidate.ServiceId, ServiceRunId: candidate.ServiceRunId,
			RunNumber: candidate.RunNumber, EndpointRevision: 1, Protocol: controlv1.ServiceProtocolHTTP,
			Hostname: "route.example", Port: 443, ValidUntil: privateMinTime(candidate.ExpiresAt, snapshot.ValidUntil),
			Anonymous: c.anonymous, ConnectedRelays: candidate.ConnectedRelays, Traffic: candidate.Traffic}
		authority, key, err := visitortoken.IssueVisitorSourceAuthority([32]byte{1}, tunnelv1.VisitorSourceAuthority{
			ServiceID: run.ServiceId, ServiceRunID: run.ServiceRunId, RunNumber: uint64(run.RunNumber), EndpointRevision: run.EndpointRevision,
			IngressID: id, IngressRunID: lease.IngressRunId, IngressLeaseRevision: uint64(lease.IngressLeaseRevision),
			VisitorPolicyRevision: 1, ValidUntil: run.ValidUntil.Unix(),
		}, now)
		if err != nil {
			return snapshot, err
		}
		run.SourceAuthority, err = authority.MarshalBinary()
		if err != nil {
			return snapshot, err
		}
		run.SourceKey = key[:]
		snapshot.Runs = append(snapshot.Runs, run)
	}
	return snapshot, nil
}

func (c *serviceSelectionControl) AdmitPublicServiceVisitor(ctx context.Context, id string, claim ingressv1.PublicServiceVisitorClaim) (ingressv1.PublicServiceVisitorAdmission, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if claim.RunCursor != nil {
		copy := *claim.RunCursor
		claim.RunCursor = &copy
	}
	c.claims = append(c.claims, claim)
	deadline, _ := ctx.Deadline()
	c.deadlines = append(c.deadlines, deadline)
	c.actions = append(c.actions, "admit "+claim.VisitorConnectionId)
	if !c.native || id != "ingress-a" || claim.IngressLeaseRevision != 1 ||
		claim.ObservedSourceIp != "192.0.2.4" || claim.DestinationPort != 20000 {
		return ingressv1.PublicServiceVisitorAdmission{}, ErrServiceAdmission
	}
	runs := slices.Clone(c.runs)
	if cursor := claim.RunCursor; cursor != nil {
		slices.SortFunc(runs, func(a, b ingressv1.PublicServiceVisitorAdmission) int {
			aWrap, bWrap := a.RunNumber <= cursor.Start.RunNumber, b.RunNumber <= cursor.Start.RunNumber
			if aWrap != bWrap {
				if aWrap {
					return 1
				}
				return -1
			}
			return int(a.RunNumber - b.RunNumber)
		})
	}
	for _, run := range runs {
		if len(run.ConnectedRelays) == 0 {
			continue
		}
		if claim.RunCursor != nil && !serviceRunCursorAllows(*claim.RunCursor, run.RunNumber) {
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
	before   func(tunnelv1.ServiceForwardingHeader)
	port     uint16
}

func (f *serviceSelectionForwarder) OpenService(ctx context.Context, relay ingressv1.ServiceRelay, header tunnelv1.ServiceForwardingHeader, reserveCapacity func(context.Context) error) (net.Conn, error) {
	f.mu.Lock()
	f.observed = append(f.observed, header)
	open := f.openings[header.ServiceRunID]
	f.mu.Unlock()
	if header.Validate() != nil || header.PublicService == nil || header.PublicService.DestinationPort != f.port ||
		header.PublisherConnectionID != relay.PublisherConnectionId || header.ConnectionSlot != uint8(relay.ConnectionSlot) {
		return nil, ErrServiceAdmission
	}
	if f.before != nil {
		f.before(header)
	}
	if open == nil {
		return nil, errors.New("unselected service run reached the relay")
	}
	return open(ctx, header, reserveCapacity)
}

func serviceSelectionConfig(t *testing.T, count int, anonymous bool) (Config, *serviceSelectionControl, *serviceSelectionForwarder) {
	t.Helper()
	config, base, _, _ := publicServiceTestConfig(t)
	base.anonymous = anonymous
	control := &serviceSelectionControl{publicServiceControlFixture: base, live: make(map[string]ingressv1.PublicServiceVisitorAdmission)}
	for number := range count {
		relay := base.relays[0]
		relay.PublisherConnectionId = publicServiceTestID(t, "pc_")
		control.runs = append(control.runs, ingressv1.PublicServiceVisitorAdmission{
			ServiceId: base.service, ServiceRunId: publicServiceTestID(t, "srun_"), RunNumber: int64(number + 1),
			ExpiresAt: time.Now().Add(time.Minute), ConnectedRelays: []ingressv1.ServiceRelay{relay}, Traffic: base.traffic,
		})
	}
	forwarder := &serviceSelectionForwarder{openings: make(map[string]serviceRelayOpening), port: 443}
	config.Control, config.Forwarder = control, forwarder
	config.RequireProxyHeader = true
	config.TrustedProxyPeers = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	return config, control, forwarder
}

func nativeServiceSelectionConfig(t *testing.T, count int) (Config, *serviceSelectionControl, *serviceSelectionForwarder) {
	t.Helper()
	config, control, forwarder := serviceSelectionConfig(t, count, false)
	control.native, forwarder.port = true, 20000
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

func serviceSelectionHTTPServer(t *testing.T, config Config) *Server {
	t.Helper()
	server := serviceSelectionServer(t, config)
	applyServiceRoutingFixture(t, server)
	return server
}

func rejectServiceSelection(t *testing.T, ctx context.Context, server *Server) error {
	t.Helper()
	connection, visitor := net.Pipe()
	defer visitor.Close()
	return server.AcceptPublic(ctx, connection, netip.MustParseAddrPort("192.0.2.4:42000"), netip.MustParseAddrPort("203.0.113.10:443"), "route.example", nil)
}

func rejectNativeServiceSelection(t *testing.T, ctx context.Context, server *Server) error {
	t.Helper()
	connection, visitor := net.Pipe()
	defer visitor.Close()
	return server.AcceptPublic(ctx, connection, netip.MustParseAddrPort("192.0.2.4:42000"), netip.MustParseAddrPort("203.0.113.10:20000"), "", nil)
}
