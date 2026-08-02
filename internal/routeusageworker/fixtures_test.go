package routeusageworker

import (
	"context"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
)

func testWorker(t *testing.T, store *routeUsageStoreStub, endpoint string, now time.Time) *Worker {
	t.Helper()
	worker, err := New(store, Config{
		WorkerID: "route_usage_worker_test", Endpoint: endpoint, Token: "secret",
		RetryInterval: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	worker.now = func() time.Time { return now }
	return worker
}

func testDeliveryWork(id uint64, key string, now time.Time) controlstate.RouteUsageDeliveryWork {
	return controlstate.RouteUsageDeliveryWork{
		DeliveryID: id, DeliveryKey: key, SourceRevision: 1, RouteID: "route_test", RouteVersion: 1,
		TeamID: "team_test", ActingIdentityID: "identity_test",
		BucketStart: now.Add(-time.Minute), BucketEnd: now, ObservedThrough: now,
		WorkerID: "route_usage_worker_test", WorkEpoch: 1, WorkExpiresAt: now.Add(time.Minute), Attempts: 1,
	}
}

type routeUsageStoreStub struct {
	work                                                    []controlstate.RouteUsageDeliveryWork
	expireErr, finalizeErr, claimErr, completeErr, retryErr error

	completed, retried, calls               []string
	expiredAt, finalizedBefore, finalizedAt time.Time
	claimWorker                             string
	claimLimit                              int
	claimAt                                 time.Time
	claimLease                              time.Duration
	completeCalls                           []completionCall
	retryCalls                              []retryCall
}

type completionCall struct {
	work controlstate.RouteUsageDeliveryWork
	now  time.Time
}

type retryCall struct {
	work    controlstate.RouteUsageDeliveryWork
	retryAt time.Time
	message string
	now     time.Time
}

func (s *routeUsageStoreStub) MarkExpiredIngressUsageRunsIncomplete(_ context.Context, now time.Time) (int, error) {
	s.calls = append(s.calls, "expire")
	s.expiredAt = now
	return 0, s.expireErr
}

func (s *routeUsageStoreStub) FinalizeRouteUsageBuckets(_ context.Context, before, now time.Time) (int, error) {
	s.calls = append(s.calls, "finalize")
	s.finalizedBefore, s.finalizedAt = before, now
	return 0, s.finalizeErr
}

func (s *routeUsageStoreStub) ClaimRouteUsageDeliveries(_ context.Context, worker string, limit int, now time.Time, lease time.Duration) ([]controlstate.RouteUsageDeliveryWork, error) {
	s.calls = append(s.calls, "claim")
	s.claimWorker, s.claimLimit, s.claimAt, s.claimLease = worker, limit, now, lease
	result := s.work
	s.work = nil
	return result, s.claimErr
}

func (s *routeUsageStoreStub) CompleteRouteUsageDelivery(_ context.Context, work controlstate.RouteUsageDeliveryWork, now time.Time) error {
	s.completed = append(s.completed, work.DeliveryKey)
	s.completeCalls = append(s.completeCalls, completionCall{work, now})
	return s.completeErr
}

func (s *routeUsageStoreStub) RetryRouteUsageDelivery(_ context.Context, work controlstate.RouteUsageDeliveryWork, retryAt time.Time, message string, now time.Time) error {
	s.retried = append(s.retried, work.DeliveryKey)
	s.retryCalls = append(s.retryCalls, retryCall{work, retryAt, message, now})
	return s.retryErr
}
