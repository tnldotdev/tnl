package ingress

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/serviceapi"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type policyDrainClient struct {
	ControlClient
	drain func(ingressv1.IngressDrainRequest) (ingressv1.IngressLease, error)
	usage func(ingressv1.IngressUsageReportBatch) error
}

func (c policyDrainClient) DrainIngress(_ context.Context, _ string, request ingressv1.IngressDrainRequest) (ingressv1.IngressLease, error) {
	return c.drain(request)
}

func (c policyDrainClient) ReportIngressUsage(_ context.Context, _ string, batch ingressv1.IngressUsageReportBatch) error {
	return c.usage(batch)
}

func TestPublicPolicyDrainJoinsRequestsAndPreservesFinalUsage(t *testing.T) {
	for _, initial := range []bool{true, false} {
		name := "refresh"
		if initial {
			name = "preparation"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				now := time.Now()
				owner := testIngressLease(now)
				event := publicPolicyEvent(now, 1, 1, "pool.example", true)
				var calls, drains, reports atomic.Int32
				started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
				releaseRequest := sync.OnceFunc(func() { close(release) })
				client := policyDrainClient{ControlClient: publicPolicyTestClient{ControlClient: leaseTestClient{
					register: func(context.Context, ingressv1.IngressRegistration) (ingressv1.IngressLease, error) {
						return owner, nil
					},
					renew: func(context.Context) (ingressv1.IngressLease, error) { return owner, nil },
					snapshot: func(context.Context) (ingressv1.IngressRoutingTableSnapshot, error) {
						return ingressv1.IngressRoutingTableSnapshot{ThroughRevision: 1, Entries: []ingressv1.IngressRoutingTableEvent{event}}, nil
					},
					events: func(ctx context.Context) (ingressv1.IngressRoutingTablePage, error) {
						<-ctx.Done()
						return ingressv1.IngressRoutingTablePage{}, ctx.Err()
					},
				}, read: func(ctx context.Context, _ string, body ingressv1.IngressVisitorPolicyRequest) (controlv1.VisitorPolicyUpdate, error) {
					if calls.Add(1) == 1 && !initial {
						return publicPolicyWire(body, "pool.example", now), nil
					}
					close(started)
					<-ctx.Done()
					close(canceled)
					<-release
					return controlv1.VisitorPolicyUpdate{}, serviceapi.NewProblemError(409, "ingress_lease_stale", "ingress is draining")
				}}, drain: func(request ingressv1.IngressDrainRequest) (ingressv1.IngressLease, error) {
					drains.Add(1)
					updated := owner
					updated.Draining, updated.DrainDeadline = true, &request.Deadline
					return updated, nil
				}, usage: func(batch ingressv1.IngressUsageReportBatch) error {
					if batch.IngressLeaseRevision != owner.IngressLeaseRevision || batch.IngressRunId != owner.IngressRunId || !batch.Complete {
						t.Error("final usage lost the process accounting identity")
					}
					reports.Add(1)
					return nil
				}}
				c := testLeaseController(t, client)
				c.renewalInterval = time.Hour
				c.publicRunPrepared = c.installedPublicPolicy
				ctx, cancel := context.WithCancel(t.Context())
				done := make(chan error, 1)
				go func() { done <- c.Run(ctx) }()
				defer func() {
					releaseRequest()
					cancel()
					if err := <-done; err != nil {
						t.Error(err)
					}
				}()
				<-started
				drained := make(chan error, 1)
				go func() { drained <- c.Drain(t.Context(), time.Now().Add(time.Minute)) }()
				synctest.Wait()
				select {
				case <-canceled:
				default:
					t.Fatal("drain did not cancel its in-flight policy request")
				}
				if drains.Load() != 0 || c.Ready(time.Now()) {
					t.Fatal("drain reached control or kept serving before policy work joined")
				}
				releaseRequest()
				if err := <-drained; err != nil {
					t.Fatal(err)
				}
				if err := c.ReportUsage(t.Context(), usageReportBatch{complete: true, observedThrough: new(time.Now())}); err != nil || reports.Load() != 1 {
					t.Fatal("late policy response cleared the final accounting lease", err)
				}
				time.Sleep(3 * time.Second)
				synctest.Wait()
				want := int32(2)
				if initial {
					want = 1
				}
				if calls.Load() != want || drains.Load() != 1 {
					t.Fatal("policy work restarted after drain", calls.Load(), drains.Load())
				}
			})
		})
	}
}
