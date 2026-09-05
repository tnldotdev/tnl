package routeusageworker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/routeusagev1"
)

func TestWorkerDeliversAcceptedItemsAndRetriesRejections(t *testing.T) {
	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	work := []controlstate.RouteUsageDeliveryWork{
		testDeliveryWork(1, "usage_report_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now),
		testDeliveryWork(2, "usage_report_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", now),
	}
	received := make(chan routeusagev1.RouteUsageBucketReportBatch, 1)
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer secret" {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		var batch routeusagev1.RouteUsageBucketReportBatch
		if err := json.NewDecoder(request.Body).Decode(&batch); err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		received <- batch
		code := routeusagev1.BatchProblemCodeNotFound
		_ = json.NewEncoder(response).Encode(routeusagev1.RouteUsageBucketReportBatchResponse{Results: []routeusagev1.BatchResult{
			{ItemId: work[1].DeliveryKey, Accepted: false, Code: &code},
			{ItemId: work[0].DeliveryKey, Accepted: true},
		}})
	}))
	t.Cleanup(receiver.Close)
	store := &routeUsageStoreStub{work: work}
	worker := testWorker(t, store, receiver.URL, now)
	found, err := worker.process(t.Context())
	if !found || err == nil {
		t.Fatalf("process = found %v, error %v", found, err)
	}
	batch := <-received
	if len(batch.Items) != 2 || batch.Items[0].Resolution != routeusagev1.Minute ||
		batch.Items[0].TeamId != work[0].TeamID || batch.Items[0].ActingIdentityId != work[0].ActingIdentityID ||
		batch.Items[0].VisitorNetworkEstimate != "0" || len(batch.Items[0].VisitorNetworkHll) == 0 {
		t.Fatalf("usage batch = %#v", batch)
	}
	if !slices.Equal(store.completed, []string{work[0].DeliveryKey}) ||
		!slices.Equal(store.retried, []string{work[1].DeliveryKey}) {
		t.Fatalf("completed %v, retried %v", store.completed, store.retried)
	}
}

func TestWorkerRetriesAmbiguousBatchResponse(t *testing.T) {
	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	work := []controlstate.RouteUsageDeliveryWork{
		testDeliveryWork(1, "usage_report_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now),
		testDeliveryWork(2, "usage_report_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", now),
	}
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(response).Encode(routeusagev1.RouteUsageBucketReportBatchResponse{Results: []routeusagev1.BatchResult{
			{ItemId: work[0].DeliveryKey, Accepted: true},
		}})
	}))
	t.Cleanup(receiver.Close)
	store := &routeUsageStoreStub{work: work}
	worker := testWorker(t, store, receiver.URL, now)
	if found, err := worker.process(t.Context()); !found || err == nil {
		t.Fatalf("process = found %v, error %v", found, err)
	}
	if len(store.completed) != 0 || !slices.Equal(store.retried, []string{work[0].DeliveryKey, work[1].DeliveryKey}) {
		t.Fatalf("completed %v, retried %v", store.completed, store.retried)
	}
}

func TestWorkerDoesNotFollowRedirects(t *testing.T) {
	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	redirected := make(chan struct{}, 1)
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/redirected" {
			redirected <- struct{}{}
			response.WriteHeader(http.StatusOK)
			return
		}
		response.Header().Set("Location", "/redirected")
		response.WriteHeader(http.StatusTemporaryRedirect)
	}))
	t.Cleanup(receiver.Close)
	store := &routeUsageStoreStub{work: []controlstate.RouteUsageDeliveryWork{
		testDeliveryWork(1, "usage_report_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now),
	}}
	worker := testWorker(t, store, receiver.URL, now)
	if found, err := worker.process(t.Context()); !found || err == nil {
		t.Fatalf("process = found %v, error %v", found, err)
	}
	select {
	case <-redirected:
		t.Fatal("worker followed redirect")
	default:
	}
}

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
	work      []controlstate.RouteUsageDeliveryWork
	completed []string
	retried   []string
}

func (*routeUsageStoreStub) MarkExpiredIngressUsageRunsIncomplete(context.Context, time.Time) (int, error) {
	return 0, nil
}

func (*routeUsageStoreStub) FinalizeRouteUsageBuckets(
	context.Context, time.Time, time.Time,
) (int, error) {
	return 0, nil
}

func (s *routeUsageStoreStub) ClaimRouteUsageDeliveries(
	context.Context, string, int, time.Time, time.Duration,
) ([]controlstate.RouteUsageDeliveryWork, error) {
	result := s.work
	s.work = nil
	return result, nil
}

func (s *routeUsageStoreStub) CompleteRouteUsageDelivery(
	_ context.Context, work controlstate.RouteUsageDeliveryWork, _ time.Time,
) error {
	s.completed = append(s.completed, work.DeliveryKey)
	return nil
}

func (s *routeUsageStoreStub) RetryRouteUsageDelivery(
	_ context.Context,
	work controlstate.RouteUsageDeliveryWork,
	_ time.Time,
	_ string,
	_ time.Time,
) error {
	s.retried = append(s.retried, work.DeliveryKey)
	return nil
}
