package ingress

import (
	"context"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestVisitorSourceSequenceSurvivesTemporaryRoutingRemoval(t *testing.T) {
	for _, snapshot := range []bool{false, true} {
		name := "tombstone"
		if snapshot {
			name = "resnapshot"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				now := time.Now()
				event := publicPolicyEvent(now, 1, 1, "pool.example", true)
				client := publicPolicyTestClient{read: func(_ context.Context, _ string, body ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
					return publicPolicyWire(body, "pool.example", now), nil
				}}
				c := testLeaseController(t, client)
				if err := c.setLease(testIngressLease(now)); err != nil {
					t.Fatal(err)
				}
				if err := c.routingTable.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 1, Entries: []ingressv1.IngressRoutingTableEvent{event}}); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan error, 1)
				go func() { done <- c.publicPolicyLoop(ctx) }()
				defer func() {
					cancel()
					if err := <-done; err != nil {
						t.Error(err)
					}
				}()
				tick := func() { time.Sleep(100 * time.Millisecond); synctest.Wait() }
				sign := func() tunnelv1.VisitorSourceProof {
					wire, err := c.SignVisitorSource(event.Entry, "visitor", netip.MustParseAddrPort("192.0.2.1:1234"), netip.MustParseAddrPort("203.0.113.1:443"))
					if err != nil {
						t.Fatal(err)
					}
					proof, err := tunnelv1.ReadVisitorSourceProof([]byte(wire))
					if err != nil {
						t.Fatal(err)
					}
					return proof
				}
				tick()
				first := sign()
				if snapshot {
					if err := c.routingTable.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 2}); err != nil {
						t.Fatal(err)
					}
				} else {
					removed := event
					removed.Kind, removed.RoutingTableRevision, removed.EntryRevision = ingressv1.PublicUrlTombstone, 2, 2
					removed.PublicUrlExpiresAt, removed.Entry.PublisherConnections = nil, nil
					if err := c.routingTable.ApplyPage(1, ingressv1.IngressRoutingTablePage{ThroughRevision: 2, NextRevision: 2, Events: []ingressv1.IngressRoutingTableEvent{removed}}); err != nil {
						t.Fatal(err)
					}
				}
				tick()
				c.mu.RLock()
				installed := len(c.publicPolicies)
				c.mu.RUnlock()
				if installed != 0 {
					t.Fatal("removed run retained policy authority")
				}
				event.RoutingTableRevision, event.EntryRevision = 3, 3
				if err := c.routingTable.ApplyPage(2, ingressv1.IngressRoutingTablePage{ThroughRevision: 3, NextRevision: 3, Events: []ingressv1.IngressRoutingTableEvent{event}}); err != nil {
					t.Fatal(err)
				}
				tick()
				recovered := sign()
				if string(first.Authority.MAC) != string(recovered.Authority.MAC) || recovered.Sequence <= first.Sequence {
					t.Fatal("routing recovery reused a consumed source sequence", first.Sequence, recovered.Sequence)
				}
				if err := c.routingTable.ApplySnapshot(ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 4}); err != nil {
					t.Fatal(err)
				}
				tick()
				time.Sleep(visitortoken.PolicyLifetime + time.Second)
				synctest.Wait()
				c.mu.RLock()
				retained := len(c.sourceSequences)
				c.mu.RUnlock()
				if retained != 0 {
					t.Fatal("expired absent runs retained source counters", retained)
				}
			})
		})
	}
}
