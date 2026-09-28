package publicurlusageworker

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/publicurlusagev1"
)

func TestWorkerDoesNotRetryPermanentlyRejectedUsageReport(t *testing.T) {
	now := time.Date(2026, time.September, 27, 12, 0, 0, 0, time.UTC)
	work := testDeliveryWork(1, "usage_report_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now)
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		code := publicurlusagev1.BatchProblemCodeInvalidArgument
		_ = json.NewEncoder(response).Encode(publicurlusagev1.PublicURLUsageBucketReportBatchResponse{Results: []publicurlusagev1.BatchResult{{ItemId: work.DeliveryKey, Accepted: false, Code: &code}}})
	}))
	t.Cleanup(receiver.Close)
	store := &publicURLUsageStoreStub{work: []controlstate.PublicURLUsageDeliveryWork{work}}
	worker := testWorker(t, store, receiver.URL, now)
	if found, err := worker.process(t.Context()); !found || err == nil {
		t.Fatalf("process permanently rejected report: found=%t error=%v", found, err)
	}
	if len(store.retried) != 0 || len(store.completed) != 0 || len(store.rejected) != 1 || store.rejected[0] != work.DeliveryKey {
		t.Fatalf("immutable report was not quarantined after invalid_argument: retried=%v completed=%v rejected=%v", store.retried, store.completed, store.rejected)
	}
}
