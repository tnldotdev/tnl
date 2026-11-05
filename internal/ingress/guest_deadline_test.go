package ingress

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestGuestPreparationAcknowledgesPolicyWithoutAdmittingVisitors(t *testing.T) {
	for _, guest := range []bool{true, false} {
		t.Run(map[bool]string{true: "guest", false: "ordinary"}[guest], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				now := time.Now()
				var calls atomic.Int64
				client := publicPolicyTestClient{read: func(_ context.Context, _ string, body ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
					calls.Add(1)
					response := publicPolicyWire(body, "pool.example", time.Now())
					if guest {
						response.Policy.ConnectionDeadline = new(response.Policy.ValidUntil)
					}
					return response, nil
				}}
				c := testLeaseController(t, client)
				c.publicRunPrepared = c.installedPublicPolicy
				owner := testIngressLease(now)
				owner.LeaseExpiresAt = now.Add(time.Minute)
				if err := c.setLease(owner); err != nil {
					t.Fatal(err)
				}
				event := publicPolicyEvent(now, 1, 1, "pool.example", false)
				event.Entry.PublicUrlExpiresAt = now.Add(time.Minute)
				event.PublicUrlExpiresAt = &event.Entry.PublicUrlExpiresAt
				if err := c.routingTable.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 1, Entries: []ingressv1.IngressRoutingTableEvent{event}}); err != nil {
					t.Fatal(err)
				}
				c.markRoutingTableCurrent(true)
				run, err := c.preparePublicPolicy(t.Context(), event.Entry, owner)
				if err != nil {
					t.Fatal(err)
				}
				defer run.close()
				c.publicPolicies[event.Entry.PublishRunId] = run
				source, destination := netip.MustParseAddrPort("192.0.2.1:1234"), netip.MustParseAddrPort("203.0.113.1:443")
				for range 3 {
					if observations := c.publicRunObservations(owner, time.Now()); len(observations) != 1 || !observations[0].ValidUntil.After(time.Now()) {
						t.Fatal("preparation cannot acknowledge installed policy", observations)
					}
					_, reason := c.Lookup("pool.example", time.Now())
					proof, proofErr := c.SignVisitorSource(event.Entry, "visitor", source, destination)
					release, bindErr := c.BindPublicConnection(event.Entry, func() {})
					if release != nil {
						release()
					}
					if guest {
						if reason != LookupNoBackends || proof != "" || !errors.Is(proofErr, visitortoken.ErrVisitorSource) || !errors.Is(bindErr, visitortoken.ErrPolicy) {
							t.Fatalf("preparation admitted guest traffic: lookup=%s proof=%v bind=%v", reason, proofErr, bindErr)
						}
					} else if reason != LookupCurrent || proof == "" || proofErr != nil || bindErr != nil {
						t.Fatalf("ordinary preparation changed: lookup=%s proof=%v bind=%v", reason, proofErr, bindErr)
					}
					time.Sleep(4 * time.Second)
					synctest.Wait()
				}
				if calls.Load() < 3 {
					t.Fatal("test did not renew preparation")
				}
				ready := event
				ready.Entry.PublishRunReadyAt = new(time.Now())
				ready.EntryRevision, ready.RoutingTableRevision = 2, 2
				if err := c.routingTable.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 2, Entries: []ingressv1.IngressRoutingTableEvent{ready}}); err != nil {
					t.Fatal(err)
				}
				if _, reason := c.Lookup("pool.example", time.Now()); reason != LookupCurrent {
					t.Fatal("ready projection did not enable visitors", reason)
				}
				if _, err := c.SignVisitorSource(ready.Entry, "ready-visitor", source, destination); err != nil {
					t.Fatal("ready projection could not sign visitor source", err)
				}
				release, err := c.BindPublicConnection(ready.Entry, func() {})
				if err != nil || guest && release == nil {
					t.Fatal("ready projection could not bind a guest connection", err)
				}
				if release != nil {
					release()
				}
				if guest {
					if _, err := c.BindPublicConnection(event.Entry, func() {}); !errors.Is(err, visitortoken.ErrPolicy) {
						t.Fatal("retained preparation projection acquired ready authority", err)
					}
				}
			})
		})
	}
}

func TestGuestConnectionDeadlineClosesIngressSocketDuringControlOutage(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		now := time.Now()
		var offline atomic.Bool
		var rejected atomic.Int64
		client := publicPolicyTestClient{read: func(_ context.Context, _ string, body ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
			if offline.Load() {
				rejected.Add(1)
				return controlv1.VisitorPolicyUpdate{}, errors.New("control unavailable")
			}
			response := publicPolicyWire(body, "pool.example", now)
			response.Policy.ConnectionDeadline = new(response.Policy.ValidUntil)
			return response, nil
		}}
		c := testLeaseController(t, client)
		owner := testIngressLease(now)
		owner.LeaseExpiresAt = now.Add(time.Minute)
		if err := c.setLease(owner); err != nil {
			t.Fatal(err)
		}
		entry := publicPolicyEvent(now, 1, 1, "pool.example", true).Entry
		entry.PublicUrlExpiresAt = now.Add(time.Minute)
		run, err := c.preparePublicPolicy(t.Context(), entry, owner)
		if err != nil {
			t.Fatal(err)
		}
		defer run.close()
		c.publicPolicies[entry.PublishRunId] = run
		connection, visitor := net.Pipe()
		defer connection.Close()
		defer visitor.Close()
		release, err := c.BindPublicConnection(entry, func() { _ = connection.Close() })
		if err != nil || release == nil {
			t.Fatal("guest transport was not bound", err)
		}
		defer release()
		offline.Store(true)
		closed := make(chan error, 1)
		go func() { _, err := visitor.Read(make([]byte, 1)); closed <- err }()
		time.Sleep(9 * time.Second)
		synctest.Wait()
		select {
		case err := <-closed:
			t.Fatal("connection closed before its confirmed horizon", err)
		default:
		}
		time.Sleep(time.Second)
		synctest.Wait()
		select {
		case err := <-closed:
			if !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
		default:
			t.Fatal("ingress retained an idle guest socket after local expiry")
		}
		if rejected.Load() == 0 || !c.Lease().LeaseExpiresAt.After(time.Now()) {
			t.Fatal("test did not isolate guest expiry from the process lease")
		}
	})
}
