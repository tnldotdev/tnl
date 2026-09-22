package ingress

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

type challengeAckClient struct {
	leaseTestClient
	renewRequest func(context.Context, ingressv1.IngressRenewal) (ingressv1.IngressLease, error)
}

func (c challengeAckClient) RenewIngress(ctx context.Context, _ ingressv1.IngressID, request ingressv1.IngressRenewal) (ingressv1.IngressLease, error) {
	return c.renewRequest(ctx, request)
}

func TestControllerCoalescesChallengeAcknowledgments(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		pages := make(chan ingressv1.IngressRoutingTablePage)
		release := make(chan struct{})
		renewals := make(chan ingressv1.IngressRenewal, 8)
		first := true
		client := challengeAckClient{leaseTestClient: leaseTestClient{
			register: func(context.Context, ingressv1.IngressRegistration) (ingressv1.IngressLease, error) {
				return testIngressLease(start), nil
			},
			snapshot: func(context.Context) (ingressv1.IngressRoutingTableSnapshot, error) {
				return ingressv1.IngressRoutingTableSnapshot{}, nil
			},
			events: func(ctx context.Context) (ingressv1.IngressRoutingTablePage, error) {
				select {
				case page := <-pages:
					return page, nil
				case <-ctx.Done():
					return ingressv1.IngressRoutingTablePage{}, ctx.Err()
				}
			},
		}}
		controller := testLeaseController(t, client)
		controller.renewalInterval = 10 * time.Second
		client.renewRequest = func(ctx context.Context, request ingressv1.IngressRenewal) (ingressv1.IngressLease, error) {
			revision, _ := controller.routingTable.Revision()
			if request.RoutingTableRevision > revision || request.IngressRunId != "run" || request.IngressLeaseRevision != 1 {
				t.Errorf("acknowledged unapplied state or wrong identity: %+v (applied %d)", request, revision)
			}
			renewals <- request
			if first {
				first = false
				select {
				case <-release:
				case <-ctx.Done():
					return ingressv1.IngressLease{}, ctx.Err()
				}
			}
			lease := testIngressLease(start)
			lease.RenewedAt, lease.LeaseExpiresAt = time.Now(), time.Now().Add(time.Minute)
			lease.RoutingTableRevision = request.RoutingTableRevision
			return lease, nil
		}
		controller.client = client
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- controller.Run(ctx) }()
		defer func() {
			cancel()
			if err := <-done; err != nil {
				t.Error(err)
			}
		}()
		send := func(revision int64, kind ingressv1.IngressRoutingTableEventKind) {
			event := routingReliabilityEvent(start, revision)
			event.Kind = kind
			pages <- ingressv1.IngressRoutingTablePage{ThroughRevision: revision, NextRevision: revision, Events: []ingressv1.IngressRoutingTableEvent{event}}
			synctest.Wait()
		}
		send(1, ingressv1.RouteUpsert)
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if len(renewals) != 0 {
			t.Fatal("ordinary route update triggered early renewal")
		}
		send(2, ingressv1.ChallengeUpsert)
		time.Sleep(50 * time.Millisecond)
		for revision := int64(3); revision <= 4; revision++ {
			send(revision, ingressv1.ChallengeUpsert)
		}
		time.Sleep(50 * time.Millisecond)
		synctest.Wait()
		if len(renewals) != 1 || (<-renewals).RoutingTableRevision != 4 {
			t.Fatal("challenge burst was not acknowledged once at revision 4")
		}
		// Routing continues during a blocked renewal; only one renewal can be in flight.
		send(5, ingressv1.ChallengeUpsert)
		send(6, ingressv1.ChallengeUpsert)
		time.Sleep(time.Second)
		synctest.Wait()
		if len(renewals) != 0 {
			t.Fatal("concurrent renewal while acknowledgment blocked")
		}
		close(release)
		synctest.Wait()
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		if len(renewals) != 1 || (<-renewals).RoutingTableRevision != 6 {
			t.Fatal("lost in-flight routing progress")
		}
		time.Sleep(10*time.Second - time.Nanosecond)
		synctest.Wait()
		if len(renewals) != 0 {
			t.Fatal("periodic renewal was not reset after acknowledgment")
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if len(renewals) != 1 {
			t.Fatal("periodic renewal stopped after acknowledgment")
		}
	})
}

func TestControllerAcknowledgesChallengeSnapshots(t *testing.T) {
	for _, mode := range []string{"initial", "resnapshot", "invalid-page", "invalid-snapshot", "cancel-batch", "cancel-renewal"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				event := routingReliabilityEvent(start, 1)
				event.Kind = ingressv1.ChallengeUpsert
				invalid := mode == "invalid-page" || mode == "invalid-snapshot"
				if invalid {
					event.Entry.RouteId = "mismatched"
				}
				var snapshots, requests int
				renewals := make(chan ingressv1.IngressRenewal, 8)
				client := challengeAckClient{leaseTestClient: leaseTestClient{
					register: func(context.Context, ingressv1.IngressRegistration) (ingressv1.IngressLease, error) {
						return testIngressLease(start), nil
					},
					snapshot: func(context.Context) (ingressv1.IngressRoutingTableSnapshot, error) {
						snapshots++
						if mode == "invalid-page" || mode == "resnapshot" && snapshots == 1 {
							return ingressv1.IngressRoutingTableSnapshot{}, nil
						}
						return ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 1, Entries: []ingressv1.IngressRoutingTableEvent{event}}, nil
					},
					events: func(ctx context.Context) (ingressv1.IngressRoutingTablePage, error) {
						requests++
						if requests == 1 && mode == "resnapshot" {
							return ingressv1.IngressRoutingTablePage{}, serviceapi.NewProblemError(409, "routing_table_resnapshot_required", "snapshot required")
						}
						if mode == "invalid-page" {
							return ingressv1.IngressRoutingTablePage{ThroughRevision: 1, NextRevision: 1, Events: []ingressv1.IngressRoutingTableEvent{event}}, nil
						}
						<-ctx.Done()
						return ingressv1.IngressRoutingTablePage{}, ctx.Err()
					},
				}, renewRequest: func(ctx context.Context, request ingressv1.IngressRenewal) (ingressv1.IngressLease, error) {
					renewals <- request
					if request.RoutingTableRevision != 1 {
						t.Errorf("acknowledged revision %d", request.RoutingTableRevision)
					}
					if mode == "cancel-renewal" {
						<-ctx.Done()
						return ingressv1.IngressLease{}, ctx.Err()
					}
					return testIngressLease(start), nil
				}}
				controller := testLeaseController(t, client)
				controller.renewalInterval = 10 * time.Second
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- controller.runOnce(ctx) }()
				synctest.Wait()
				if invalid {
					if err := <-done; err == nil {
						t.Fatal("invalid routing state accepted")
					}
					if len(renewals) != 0 {
						t.Fatal("invalid routing state acknowledged")
					}
					return
				}
				wait, want := 100*time.Millisecond, 1
				if mode == "cancel-batch" {
					wait, want = 50*time.Millisecond, 0
				}
				time.Sleep(wait)
				synctest.Wait()
				if len(renewals) != want {
					t.Errorf("snapshot acknowledgments = %d, want %d", len(renewals), want)
				}
				cancel()
				if err := <-done; err != nil {
					t.Error(err)
				}
			})
		})
	}
}
