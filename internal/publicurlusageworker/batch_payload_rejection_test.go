package publicurlusageworker

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/publicurlusagev1"
)

func TestWorkerRetiresSingleReportRejectedAsTooLarge(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	work := testDeliveryWork(1, "usage_report_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now)
	requests := 0
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests++
		response.WriteHeader(http.StatusRequestEntityTooLarge)
	}))
	t.Cleanup(receiver.Close)
	store := &publicURLUsageStoreStub{work: []controlstate.PublicURLUsageDeliveryWork{work}}
	worker := testWorker(t, store, receiver.URL, now)
	if found, err := worker.process(t.Context()); !found || err == nil {
		t.Fatalf("process rejected report: found=%t error=%v", found, err)
	}
	if requests != 1 || len(store.retried) != 0 || len(store.rejected) != 1 || store.rejected[0] != work.DeliveryKey {
		t.Fatalf("unchanged report will be resent after HTTP 413: requests=%d retried=%v rejected=%v", requests, store.retried, store.rejected)
	}
}

func TestWorkerSplitsBatchRejectedAsTooLarge(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	work := []controlstate.PublicURLUsageDeliveryWork{
		testDeliveryWork(1, "usage_report_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now),
		testDeliveryWork(2, "usage_report_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", now),
	}
	requests := 0
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests++
		var batch publicurlusagev1.PublicURLUsageBucketReportBatch
		if err := json.NewDecoder(request.Body).Decode(&batch); err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(batch.Items) > 1 {
			response.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		_ = json.NewEncoder(response).Encode(publicurlusagev1.PublicURLUsageBucketReportBatchResponse{
			Results: []publicurlusagev1.BatchResult{{ItemId: batch.Items[0].ItemId, Accepted: true}},
		})
	}))
	t.Cleanup(receiver.Close)
	store := &publicURLUsageStoreStub{work: work}
	worker := testWorker(t, store, receiver.URL, now)
	if found, err := worker.process(t.Context()); !found || err != nil {
		t.Fatalf("split rejected batch: found=%t error=%v", found, err)
	}
	if requests != 3 || !slices.Equal(store.completed, []string{work[0].DeliveryKey, work[1].DeliveryKey}) || len(store.retried) != 0 || len(store.rejected) != 0 {
		t.Fatalf("split batch: requests=%d completed=%v retried=%v rejected=%v", requests, store.completed, store.retried, store.rejected)
	}
}
