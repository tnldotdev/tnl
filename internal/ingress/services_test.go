package ingress

import (
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func serviceRoutingFixture(t *testing.T) (ingressv1.IngressLease, ingressv1.IngressServices) {
	t.Helper()
	_, control, _, lease := publicServiceTestConfig(t)
	now := time.Now()
	master := [32]byte{1}
	authority, key, err := visitortoken.IssueVisitorSourceAuthority(master, tunnelv1.VisitorSourceAuthority{
		ServiceID: control.service, ServiceRunID: control.run, RunNumber: 1, EndpointRevision: 1,
		IngressID: lease.IngressId, IngressRunID: lease.IngressRunId, IngressLeaseRevision: uint64(lease.IngressLeaseRevision),
		VisitorPolicyRevision: 1, ValidUntil: now.Add(visitortoken.PolicyLifetime).Unix(),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := authority.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return lease, ingressv1.IngressServices{ObservedAt: now, ValidUntil: now.Add(visitortoken.PolicyLifetime),
		Runs: []ingressv1.IngressServiceRun{{
			ServiceId: control.service, ServiceRunId: control.run, RunNumber: 1, Protocol: "http",
			Hostname: "route.example", Port: 443, EndpointRevision: 1, ValidUntil: now.Add(visitortoken.PolicyLifetime),
			Traffic: control.traffic, ConnectedRelays: control.relays, SourceAuthority: wire, SourceKey: key[:],
		}}}
}

func TestServiceRoutingSelectsExactEndpointAndExpiresWithoutControl(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, snapshot := serviceRoutingFixture(t)
		routing := NewServiceRouting()
		defer routing.Close()
		started := time.Now()
		if err := routing.apply(started, lease, snapshot); err != nil {
			t.Fatal(err)
		}
		server := &Server{services: routing}
		if !server.RoutingObservedAt().Equal(snapshot.ObservedAt) {
			t.Fatal("routing observation did not retain control's snapshot time")
		}
		for _, endpoint := range []serviceEndpoint{{"other.example", 443}, {"route.example", 8443}, {"", 443}} {
			if routes := routing.lookup(endpoint.hostname, endpoint.port, lease, time.Now()); len(routes) != 0 {
				t.Fatal("routing chose a different endpoint", endpoint)
			}
		}
		routes := routing.lookup("route.example", 443, lease, time.Now())
		if len(routes) != 1 || routes[0].run.ServiceId != snapshot.Runs[0].ServiceId {
			t.Fatal("exact HTTP endpoint was not selected")
		}
		var closed atomic.Int32
		release, err := routing.bind(routes[0], netip.MustParseAddr("192.0.2.4"), func() { closed.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		time.Sleep(visitortoken.PolicyLifetime)
		synctest.Wait()
		if routes := routing.lookup("route.example", 443, lease, time.Now()); len(routes) != 0 || closed.Load() != 1 {
			t.Fatal("routing or an active visitor outlived its original deadline", len(routes), closed.Load())
		}
		if err := routing.apply(started, lease, snapshot); err == nil || closed.Load() != 1 {
			t.Fatal("a late response revived expired serving state")
		}
	})
}

func TestServiceRoutingRejectsAnonymousNativeService(t *testing.T) {
	lease, snapshot := serviceRoutingFixture(t)
	routing := NewServiceRouting()
	defer routing.Close()
	snapshot.Runs[0].Protocol, snapshot.Runs[0].Port, snapshot.Runs[0].Anonymous = "tcp", 25443, true
	if err := routing.apply(time.Now(), lease, snapshot); err == nil {
		t.Fatal("native service claimed anonymous HTTP visitor policy")
	}
	snapshot.Runs[0].Anonymous = false
	if err := routing.apply(time.Now(), lease, snapshot); err != nil {
		t.Fatal("valid native fixture was rejected", err)
	}
}

func TestServiceRoutingReplacesStateAndClosesOnlyChangedEndpoints(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, snapshot := serviceRoutingFixture(t)
		routing := NewServiceRouting()
		defer routing.Close()
		if err := routing.apply(time.Now(), lease, snapshot); err != nil {
			t.Fatal(err)
		}
		route := routing.lookup("route.example", 443, lease, time.Now())[0]
		var closed atomic.Int32
		release, err := routing.bind(route, netip.MustParseAddr("192.0.2.4"), func() { closed.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		time.Sleep(time.Second)
		_, fresh := serviceRoutingFixture(t)
		// the fixture creates fresh IDs; keep the same actual service and run.
		fresh.Runs = snapshot.Runs
		fresh.Runs[0].ValidUntil = fresh.ValidUntil
		if err := routing.apply(time.Now(), lease, fresh); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if closed.Load() != 0 {
			t.Fatal("a normal refresh closed an unchanged visitor")
		}
		time.Sleep(time.Second)
		fresh.ObservedAt = time.Now()
		fresh.ValidUntil = time.Now().Add(visitortoken.PolicyLifetime)
		fresh.Runs[0].ValidUntil = fresh.ValidUntil
		fresh.Runs[0].EndpointRevision++
		master := [32]byte{1}
		authority, err := tunnelv1.ReadVisitorSourceAuthority(fresh.Runs[0].SourceAuthority)
		if err != nil {
			t.Fatal(err)
		}
		authority.EndpointRevision++
		authority, key, err := visitortoken.IssueVisitorSourceAuthority(master, authority, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		fresh.Runs[0].SourceKey = key[:]
		fresh.Runs[0].SourceAuthority, err = authority.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if err := routing.apply(time.Now(), lease, fresh); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if closed.Load() != 1 {
			t.Fatal("an endpoint change retained the previous public connection")
		}
		fresh.Runs = nil
		time.Sleep(time.Second)
		fresh.ObservedAt = time.Now()
		fresh.ValidUntil = time.Now().Add(visitortoken.PolicyLifetime)
		if err := routing.apply(time.Now(), lease, fresh); err != nil {
			t.Fatal(err)
		}
		if routes := routing.lookup("route.example", 443, lease, time.Now()); len(routes) != 0 {
			t.Fatal("a service missing from the new snapshot remained selectable")
		}
	})
}

func TestServiceRoutingRejectsWrongLeaseAndOutOfOrderSnapshots(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, snapshot := serviceRoutingFixture(t)
		routing := NewServiceRouting()
		defer routing.Close()
		started := time.Now()
		if err := routing.apply(started, lease, snapshot); err != nil {
			t.Fatal(err)
		}
		other := lease
		other.IngressLeaseRevision++
		if routes := routing.lookup("route.example", 443, other, time.Now()); len(routes) != 0 {
			t.Fatal("a different ingress lease used installed routing")
		}
		if err := routing.apply(started.Add(-time.Second), lease, snapshot); err == nil {
			t.Fatal("an older request replaced newer state")
		}
		time.Sleep(time.Second)
		if err := routing.apply(time.Now(), lease, snapshot); err == nil {
			t.Fatal("the same snapshot extended its original deadline")
		}
		invalid := snapshot
		invalid.ValidUntil = invalid.ValidUntil.Add(time.Second)
		if err := routing.apply(time.Now(), lease, invalid); err == nil {
			t.Fatal("routing accepted a longer authorization lifetime")
		}
		if routes := routing.lookup("route.example", 443, lease, time.Now()); len(routes) != 1 {
			t.Fatal("a rejected snapshot removed the current valid state")
		}
	})
}

func TestServiceRoutingClosesVisitorsAtIngressLeaseExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, snapshot := serviceRoutingFixture(t)
		lease.LeaseExpiresAt = time.Now().Add(time.Second)
		routing := NewServiceRouting()
		defer routing.Close()
		if err := routing.apply(time.Now(), lease, snapshot); err != nil {
			t.Fatal(err)
		}
		route := routing.lookup("route.example", 443, lease, time.Now())[0]
		var stopped atomic.Int32
		release, err := routing.bind(route, netip.MustParseAddr("192.0.2.4"), func() { stopped.Add(1) })
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		time.Sleep(time.Second)
		synctest.Wait()
		if stopped.Load() != 1 {
			t.Fatal("a public connection outlived the ingress lease", stopped.Load())
		}
	})
}

func TestServiceRoutingCloseWaitsForConnectionStops(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, snapshot := serviceRoutingFixture(t)
		routing := NewServiceRouting()
		defer routing.Close()
		if err := routing.apply(time.Now(), lease, snapshot); err != nil {
			t.Fatal(err)
		}
		route := routing.lookup("route.example", 443, lease, time.Now())[0]
		entered, finish := make(chan struct{}), make(chan struct{})
		release, err := routing.bind(route, netip.MustParseAddr("192.0.2.4"), func() {
			close(entered)
			<-finish
		})
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		done := make(chan struct{})
		go func() { routing.Close(); close(done) }()
		<-entered
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("routing close returned before its connection stop finished")
		default:
		}
		close(finish)
		<-done
	})
}

func TestServiceRoutingBindChecksCurrentEndpointAndOriginalDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lease, snapshot := serviceRoutingFixture(t)
		routing := NewServiceRouting()
		defer routing.Close()
		if err := routing.apply(time.Now(), lease, snapshot); err != nil {
			t.Fatal(err)
		}
		old := routing.lookup("route.example", 443, lease, time.Now())[0]
		time.Sleep(time.Second)
		snapshot.ObservedAt = time.Now()
		snapshot.ValidUntil = time.Now().Add(visitortoken.PolicyLifetime)
		snapshot.Runs[0].ValidUntil = snapshot.ValidUntil
		if err := routing.apply(time.Now(), lease, snapshot); err != nil {
			t.Fatal(err)
		}
		release, err := routing.bind(old, netip.MustParseAddr("192.0.2.4"), func() {})
		if err != nil {
			t.Fatal("a normal refresh interrupted unchanged connection setup", err)
		}
		release()
		time.Sleep(visitortoken.PolicyLifetime)
		if release, err := routing.bind(old, netip.MustParseAddr("192.0.2.4"), func() {}); err == nil {
			release()
			t.Fatal("a refresh revived an expired opening")
		}
	})
}
