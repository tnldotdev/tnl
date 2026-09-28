package publicurlusageworker

import (
	"context"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
)

func testWorker(t *testing.T, store *publicURLUsageStoreStub, endpoint string, now time.Time) *Worker {
	t.Helper()
	worker, err := New(store, Config{
		WorkerID: "public_url_usage_worker_test", Endpoint: endpoint, Token: "secret",
		RetryInterval: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	worker.now = func() time.Time { return now }
	return worker
}

func testDeliveryWork(id uint64, key string, now time.Time) controlstate.PublicURLUsageDeliveryWork {
	return controlstate.PublicURLUsageDeliveryWork{
		DeliveryID: id, DeliveryKey: key, SourceRevision: 1, PublicURLID: "public_url_test", PublishRunNumber: 1,
		TeamID: "team_test", ActingIdentityID: "identity_test",
		BucketStart: now.Add(-time.Minute), BucketEnd: now, ObservedThrough: now,
		WorkerID: "public_url_usage_worker_test", WorkEpoch: 1, WorkExpiresAt: now.Add(time.Minute), Attempts: 1,
	}
}

type publicURLUsageStoreStub struct {
	work                                                               []controlstate.PublicURLUsageDeliveryWork
	expireErr, finalizeErr, claimErr, completeErr, retryErr, rejectErr error

	completed, retried, rejected, calls     []string
	expiredAt, finalizedBefore, finalizedAt time.Time
	claimWorker                             string
	claimLimit                              int
	claimAt                                 time.Time
	claimLease                              time.Duration
	completeCalls                           []completionCall
	retryCalls                              []retryCall
}

type completionCall struct {
	work controlstate.PublicURLUsageDeliveryWork
	now  time.Time
}

type retryCall struct {
	work    controlstate.PublicURLUsageDeliveryWork
	retryAt time.Time
	message string
	now     time.Time
}

func (s *publicURLUsageStoreStub) MarkExpiredIngressUsageRunsIncomplete(_ context.Context, now time.Time) (int, error) {
	s.calls = append(s.calls, "expire")
	s.expiredAt = now
	return 0, s.expireErr
}

func (s *publicURLUsageStoreStub) FinalizePublicURLUsageBuckets(_ context.Context, before, now time.Time) (int, error) {
	s.calls = append(s.calls, "finalize")
	s.finalizedBefore, s.finalizedAt = before, now
	return 0, s.finalizeErr
}

func (s *publicURLUsageStoreStub) ClaimPublicURLUsageDeliveries(_ context.Context, worker string, limit int, now time.Time, lease time.Duration) ([]controlstate.PublicURLUsageDeliveryWork, error) {
	s.calls = append(s.calls, "claim")
	s.claimWorker, s.claimLimit, s.claimAt, s.claimLease = worker, limit, now, lease
	result := s.work
	s.work = nil
	return result, s.claimErr
}

func (s *publicURLUsageStoreStub) CompletePublicURLUsageDelivery(_ context.Context, work controlstate.PublicURLUsageDeliveryWork, now time.Time) error {
	s.completed = append(s.completed, work.DeliveryKey)
	s.completeCalls = append(s.completeCalls, completionCall{work, now})
	return s.completeErr
}

func (s *publicURLUsageStoreStub) RetryPublicURLUsageDelivery(_ context.Context, work controlstate.PublicURLUsageDeliveryWork, retryAt time.Time, message string, now time.Time) error {
	s.retried = append(s.retried, work.DeliveryKey)
	s.retryCalls = append(s.retryCalls, retryCall{work, retryAt, message, now})
	return s.retryErr
}

func (s *publicURLUsageStoreStub) RejectPublicURLUsageDelivery(_ context.Context, work controlstate.PublicURLUsageDeliveryWork, _ string, _ time.Time) error {
	s.rejected = append(s.rejected, work.DeliveryKey)
	return s.rejectErr
}
