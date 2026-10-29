package publisher

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestHeartbeatLeaseOnlyAdvancesAfterFullAcceptedState(t *testing.T) {
	for _, rejected := range []string{"connections", "accepted"} {
		t.Run(rejected, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				m := observability.New("publisher")
				defer m.Shutdown(context.Background())
				ctx, cancel := context.WithCancel(observability.WithMetrics(t.Context(), m))
				defer cancel()
				old := time.Now().Add(time.Minute)
				next := old.Add(time.Hour)
				observability.PublisherLease(ctx, old)
				invalid := errors.New("invalid success response")
				calls := 0
				control := &publisherControlStub{heartbeat: func(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error) {
					calls++
					if calls > 1 {
						cancel()
					}
					return controlv1.PublishRunHeartbeat{PublishRun: controlv1.PublishRun{Id: "run", PublishRunNumber: 1, ExpiresAt: next}, PublisherConnections: []controlv1.ConnectionAssignment{{}}}, nil
				}}
				err := heartbeatSessionAfterUpdate(ctx, heartbeatTestAuthority(control, "run", "token"), old, func([]controlv1.ConnectionAssignment) error {
					if rejected == "connections" {
						return invalid
					}
					return nil
				}, time.Millisecond)
				if rejected != "accepted" && !errors.Is(err, invalid) {
					t.Fatal(err)
				}
				want := old
				if rejected == "accepted" {
					want = next
				}
				families, err := m.Gather()
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, family := range families {
					if family.GetName() == "tnl_publisher_lease_expiration_timestamp_seconds" {
						found = family.Metric[0].GetGauge().GetValue() == float64(want.Unix())
					}
				}
				if !found {
					t.Fatal("rejected success response changed confirmed lease", families)
				}
			})
		})
	}
}

func TestHeartbeatRenewsShortPreparationLeaseAndStopsAtFixedBound(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		deadline := start.Add(8 * time.Second)
		var calls []time.Time
		control := &publisherControlStub{heartbeat: func(context.Context, string, uint64, credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error) {
			calls = append(calls, time.Now())
			// preparation has no ready interval yet. the first renewal still
			// grants at most eight seconds from its observation. readiness then
			// fixes that deadline; later heartbeats cannot move it.
			if len(calls) == 1 {
				deadline = time.Now().Add(8 * time.Second)
			}
			return controlv1.PublishRunHeartbeat{PublishRun: controlv1.PublishRun{Id: "run", PublishRunNumber: 1, ExpiresAt: deadline}}, nil
		}}
		err := heartbeatSessionAfterUpdate(t.Context(), heartbeatTestAuthority(control, "run", "token"), start.Add(8*time.Second), nil, 15*time.Second)
		if !errors.Is(err, clientcontrol.ErrStatusConflict) {
			t.Fatal(err)
		}
		if len(calls) < 2 || !calls[0].Equal(start.Add(4*time.Second)) || !time.Now().Equal(deadline) {
			t.Fatalf("short lease cadence calls=%v stopped=%v deadline=%v", calls, time.Now(), deadline)
		}
		for _, at := range calls {
			if !at.Before(deadline) {
				t.Fatal("heartbeat crossed its last confirmed bound")
			}
		}
	})
}
