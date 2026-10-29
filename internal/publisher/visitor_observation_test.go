package publisher

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublisherObservationExpiresWithoutInstalledRenewal(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		base := &policyClientFixture{key: ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))}
		var stalled, renewed atomic.Bool
		var observedUntil atomic.Int64
		var observations []int64
		client := policyClientFunc(func(ctx context.Context, body controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
			observedUntil.Store(0)
			if len(body.ObservedAllocations) != 0 {
				if len(body.ObservedAllocations) != 1 {
					t.Fatal("unexpected allocation observations")
				}
				observedUntil.Store(body.ObservedAllocations[0].ValidUntil.UnixNano())
			}
			observations = append(observations, observedUntil.Load())
			if stalled.Load() {
				return controlv1.VisitorPolicyUpdate{}, errors.New("policy response withheld")
			}
			wire, err := base.ReadPublisherVisitorPolicy(ctx, body, token)
			issued := start
			if renewed.Load() {
				issued = start.Add(9 * time.Second)
			}
			wire.Policy.StreamAllocations = []controlv1.StreamCapacityAllocation{{
				Id: "salloc_" + strings.Repeat("A", 22), Resource: body.Resource, RunId: body.RunId, RunNumber: body.RunNumber,
				IngressId: "ingress", IngressRunId: "process", IngressLeaseRevision: 1, Capacity: 1, ObservedAt: issued, ValidUntil: issued.Add(10 * time.Second), ReservationKey: []byte(strings.Repeat("k", 32)),
			}}
			return wire, err
		})
		policy, err := prepareVisitorPolicy(t.Context(), client, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: certificateTestPublicURLID}, "pr_"+strings.Repeat("B", 22), 1, "run-secret", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer policy.Close()
		time.Sleep(8 * time.Second)
		synctest.Wait()
		stalled.Store(true)
		renewed.Store(true)
		time.Sleep(3 * time.Second)
		synctest.Wait()
		if err := policy.refresh(t.Context()); err == nil {
			t.Fatal("withheld response unexpectedly installed")
		}
		if observedUntil.Load() != 0 {
			t.Fatal("renewed database expiry resurrected old installed publisher evidence")
		}
		if _, enabled, _ := policy.lease.Current(); !enabled {
			t.Fatal("fixture expired policy instead of its older allocation")
		}
		stalled.Store(false)
		before := len(observations)
		if err := policy.refresh(t.Context()); err != nil {
			t.Fatal(err)
		}
		if len(observations) != before+2 || observations[before] != 0 || observations[before+1] != start.Add(19*time.Second).UnixNano() {
			t.Fatal("recovery did not install before reporting the fresh allocation", observations[before:])
		}
		if err := policy.refresh(t.Context()); err != nil {
			t.Fatal(err)
		}
		if observedUntil.Load() != start.Add(19*time.Second).UnixNano() {
			t.Fatal("fresh installed allocation did not restore its bounded publisher observation")
		}
	})
}

func TestPublisherObservationFollowUpKeepsOriginalBudget(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		base := &policyClientFixture{key: ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))}
		start := time.Now()
		var calls int
		client := policyClientFunc(func(ctx context.Context, body controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
			calls++
			if calls == 1 {
				time.Sleep(time.Second)
			} else {
				if deadline, ok := ctx.Deadline(); !ok || !deadline.Equal(start.Add(2*time.Second)) {
					t.Fatal("installation follow-up reset its request budget")
				}
				<-ctx.Done()
			}
			wire, err := base.ReadPublisherVisitorPolicy(ctx, body, token)
			wire.Policy.StreamAllocations = []controlv1.StreamCapacityAllocation{{
				Id: "salloc_" + strings.Repeat("A", 22), Resource: body.Resource, RunId: body.RunId, RunNumber: body.RunNumber,
				IngressId: "ingress", IngressRunId: "process", IngressLeaseRevision: 1, Capacity: 1, ObservedAt: start, ValidUntil: start.Add(6 * time.Second), ReservationKey: []byte(strings.Repeat("k", 32)),
			}}
			return wire, err
		})
		policy, err := prepareVisitorPolicy(t.Context(), client, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: certificateTestPublicURLID}, "pr_"+strings.Repeat("B", 22), 1, "run-secret", nil)
		if policy != nil {
			policy.Close()
			t.Fatal("late installation acknowledgement published preparation")
		}
		if !errors.Is(err, context.DeadlineExceeded) || calls != 2 || time.Since(start) != 2*time.Second {
			t.Fatal("installation follow-up escaped its original budget", err, calls, time.Since(start))
		}
	})
}

func TestPublisherObservationReportsInstallationBeforeNextPoll(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		base := &policyClientFixture{key: ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32)))}
		start := time.Now()
		var calls int
		client := policyClientFunc(func(ctx context.Context, body controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
			calls++
			if calls == 1 && len(body.ObservedAllocations) != 0 {
				t.Fatal("uninstalled response was acknowledged")
			}
			if calls == 2 && (len(body.ObservedAllocations) != 1 || !body.ObservedAllocations[0].ValidUntil.Equal(start.Add(6*time.Second))) {
				t.Fatal("installed allocation was not acknowledged with its original deadline")
			}
			wire, err := base.ReadPublisherVisitorPolicy(ctx, body, token)
			wire.Policy.StreamAllocations = []controlv1.StreamCapacityAllocation{{
				Id: "salloc_" + strings.Repeat("A", 22), Resource: body.Resource, RunId: body.RunId, RunNumber: body.RunNumber,
				IngressId: "ingress", IngressRunId: "process", IngressLeaseRevision: 1, Capacity: 1, ObservedAt: start, ValidUntil: start.Add(6 * time.Second), ReservationKey: []byte(strings.Repeat("k", 32)),
			}}
			return wire, err
		})
		policy, err := prepareVisitorPolicy(t.Context(), client, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: certificateTestPublicURLID}, "pr_"+strings.Repeat("B", 22), 1, "run-secret", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer policy.Close()
		if calls != 2 || time.Now() != start {
			t.Fatal("installation waited for a later poll or used unbounded control calls", calls, time.Since(start))
		}
	})
}
