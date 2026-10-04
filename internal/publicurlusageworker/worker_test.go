package publicurlusageworker

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/pkg/api/publicurlusagev1"
)

func TestWorkerDeliversAcceptedItemsAndRetriesRejections(t *testing.T) {
	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	work := []controlstate.PublicURLUsageDeliveryWork{
		testDeliveryWork(1, "usage_report_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now),
		testDeliveryWork(2, "usage_report_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", now),
	}
	work[0].ConnectionAttempts, work[0].PolicyDenials, work[0].CapacityDenials = 11, 2, 3
	work[0].VisitorStreamOpenFailures, work[0].SuccessfulStreams = 4, 5
	work[0].ConnectionNanoseconds, work[0].IngressBytes, work[0].EgressBytes = 600, 700, 800
	work[0].Complete, work[0].SourceRevision, work[0].PublishRunNumber = true, 9, 10
	type observation struct {
		method, path, authorization string
		batch                       publicurlusagev1.PublicURLUsageBucketReportBatch
		err                         error
	}
	received := make(chan observation, 1)
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var batch publicurlusagev1.PublicURLUsageBucketReportBatch
		err := json.NewDecoder(request.Body).Decode(&batch)
		received <- observation{request.Method, request.URL.Path, request.Header.Get("Authorization"), batch, err}
		if request.Header.Get("Authorization") != "Bearer secret" {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		code := publicurlusagev1.BatchProblemCodeNotFound
		_ = json.NewEncoder(response).Encode(publicurlusagev1.PublicURLUsageBucketReportBatchResponse{Results: []publicurlusagev1.BatchResult{
			{ItemId: work[1].DeliveryKey, Accepted: false, Code: &code},
			{ItemId: work[0].DeliveryKey, Accepted: true},
		}})
	}))
	t.Cleanup(receiver.Close)
	store := &publicURLUsageStoreStub{work: work}
	worker := testWorker(t, store, receiver.URL, now)
	metrics := observability.New("control")
	worker.config.Observer = metrics
	found, err := worker.process(t.Context())
	if !found || err == nil {
		t.Fatalf("process = found %v, error %v", found, err)
	}
	var batch publicurlusagev1.PublicURLUsageBucketReportBatch
	select {
	case got := <-received:
		if got.err != nil || got.method != http.MethodPost || got.path != "/v1/public-urls/usage-bucket-reports" || got.authorization != "Bearer secret" {
			t.Fatalf("receiver request = %#v", got)
		}
		batch = got.batch
	case <-time.After(time.Second):
		t.Fatal("receiver received no request")
	}
	if len(batch.Items) != 2 || batch.Items[0].Resolution != publicurlusagev1.Minute ||
		batch.Items[0].TeamId != work[0].TeamID || batch.Items[0].ActingIdentityId != work[0].ActingIdentityID ||
		batch.Items[0].VisitorNetworkEstimate != "0" || len(batch.Items[0].VisitorNetworkHll) == 0 {
		t.Fatalf("usage batch = %#v", batch)
	}
	item := batch.Items[0]
	if item.ItemId != work[0].DeliveryKey || item.PublicUrlId != "public_url_test" || item.PublishRunNumber != "10" || item.ReportRevision != "9" ||
		item.ConnectionAttempts != "11" || item.PolicyDenials != "2" || item.CapacityDenials != "3" ||
		item.VisitorStreamOpenFailures != "4" || item.SuccessfulStreams != "5" || item.ConnectionNanoseconds != "600" ||
		item.IngressBytes != "700" || item.EgressBytes != "800" || !item.Complete ||
		!item.BucketStart.Equal(now.Add(-time.Minute)) || !item.ObservedThrough.Equal(now) {
		t.Fatalf("usage counters and identity = %#v", item)
	}
	if !slices.Equal(store.completed, []string{work[0].DeliveryKey}) ||
		!slices.Equal(store.retried, []string{work[1].DeliveryKey}) {
		t.Fatalf("completed %v, retried %v", store.completed, store.retried)
	}
	if !reflect.DeepEqual(store.retryCalls, []retryCall{{work: work[1], retryAt: now.Add(time.Second), message: "not_found", now: now}}) {
		t.Fatalf("retry calls = %#v", store.retryCalls)
	}
	response := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, want := range []string{`tnl_control_public_url_usage_items_total{result="accepted"} 1`, `tnl_control_public_url_usage_items_total{result="retried"} 1`,
		`tnl_control_public_url_usage_receiver_duration_seconds_count{outcome="success"} 1`} {
		if !strings.Contains(response.Body.String(), want) {
			t.Errorf("missing metric %q", want)
		}
	}
	if strings.Contains(response.Body.String(), work[0].DeliveryKey) || strings.Contains(response.Body.String(), work[1].DeliveryKey) {
		t.Fatal("metrics exposed a delivery key")
	}
}

func TestWorkerRetriesInvalidBatchResponses(t *testing.T) {
	now := time.Date(2026, time.September, 4, 12, 0, 0, 0, time.UTC)
	work := []controlstate.PublicURLUsageDeliveryWork{
		testDeliveryWork(1, "usage_report_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now),
		testDeliveryWork(2, "usage_report_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", now),
	}
	accepted := fmt.Sprintf(`{"item_id":%q,"accepted":true}`, work[0].DeliveryKey)
	other := fmt.Sprintf(`{"item_id":%q,"accepted":true}`, work[1].DeliveryKey)
	for _, test := range []struct{ name, body, message string }{
		{"missing result", `{"results":[` + accepted + `]}`, "result count"},
		{"duplicate result", `{"results":[` + accepted + `,` + accepted + `]}`, "duplicate item ID"},
		{"unknown result", `{"results":[` + accepted + `,{"item_id":"unknown","accepted":true}]}`, "unknown item ID"},
		{"rejected without code", fmt.Sprintf(`{"results":[%s,{"item_id":%q,"accepted":false}]}`, accepted, work[1].DeliveryKey), "invalid item result"},
		{"accepted with code", fmt.Sprintf(`{"results":[%s,{"item_id":%q,"accepted":true,"code":"not_found"}]}`, accepted, work[1].DeliveryKey), "invalid item result"},
		{"unknown code", fmt.Sprintf(`{"results":[%s,{"item_id":%q,"accepted":false,"code":"future_code"}]}`, accepted, work[1].DeliveryKey), "invalid item result"},
		{"malformed JSON", `{"results":`, "decode response"},
		{"unknown field", `{"results":[` + accepted + `,` + other + `],"extra":true}`, "decode response"},
		{"trailing JSON", `{"results":[` + accepted + `,` + other + `]} {}`, "trailing data"},
		{"oversized response", strings.Repeat(" ", maximumResponseBytes+1), "size limit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				_, _ = response.Write([]byte(test.body))
			}))
			t.Cleanup(receiver.Close)
			store := &publicURLUsageStoreStub{work: work}
			worker := testWorker(t, store, receiver.URL, now)
			found, err := worker.process(t.Context())
			if !found || err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("process = found %v, error %v; want %q", found, err, test.message)
			}
			if len(store.completed) != 0 || !slices.Equal(store.retried, []string{work[0].DeliveryKey, work[1].DeliveryKey}) {
				t.Fatalf("completed %v, retried %v", store.completed, store.retried)
			}
		})
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
	store := &publicURLUsageStoreStub{work: []controlstate.PublicURLUsageDeliveryWork{
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

func TestWorkerHousekeepingAndClaimFailures(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 23, 0, time.UTC)
	failure := errors.New("database unavailable")
	for _, test := range []struct {
		name      string
		store     publicURLUsageStoreStub
		wantCalls []string
	}{
		{"expire", publicURLUsageStoreStub{expireErr: failure}, []string{"expire"}},
		{"finalize", publicURLUsageStoreStub{finalizeErr: failure}, []string{"expire", "finalize"}},
		{"claim", publicURLUsageStoreStub{claimErr: failure}, []string{"expire", "finalize", "claim"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			worker := testWorker(t, &test.store, "http://unused.example.test", now)
			if found, err := worker.process(t.Context()); found || !errors.Is(err, failure) {
				t.Fatalf("process = %v, %v", found, err)
			}
			if !slices.Equal(test.store.calls, test.wantCalls) || len(test.store.retryCalls) != 0 || len(test.store.completeCalls) != 0 {
				t.Fatalf("store calls = %#v", test.store)
			}
		})
	}
}

func TestWorkerHousekeepingWithoutDeliveryEndpoint(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 23, 0, time.UTC)
	store := &publicURLUsageStoreStub{}
	worker, err := New(store, Config{WorkerID: "housekeeping"})
	if err != nil {
		t.Fatal(err)
	}
	worker.now = func() time.Time { return now }
	if found, err := worker.process(t.Context()); found || err != nil {
		t.Fatalf("process = %v, %v", found, err)
	}
	if !slices.Equal(store.calls, []string{"expire", "finalize"}) || !store.expiredAt.Equal(now) ||
		!store.finalizedAt.Equal(now) || !store.finalizedBefore.Equal(time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("housekeeping = %#v", store)
	}
}

func TestWorkerContinuesAfterDeliveryPersistenceFailure(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	work := []controlstate.PublicURLUsageDeliveryWork{
		testDeliveryWork(1, "usage_report_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now),
		testDeliveryWork(2, "usage_report_bbbbbbbbbbbbbbbbbbbbbbbbbbbb", now),
	}
	work[0].Attempts, work[1].Attempts = 3, 20
	failure := errors.New("lease replaced during persistence")
	for _, accepted := range []bool{true, false} {
		name := "retry"
		if accepted {
			name = "complete"
		}
		t.Run(name, func(t *testing.T) {
			receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				results := make([]publicurlusagev1.BatchResult, len(work))
				for i, item := range work {
					results[i] = publicurlusagev1.BatchResult{ItemId: item.DeliveryKey, Accepted: accepted}
					if !accepted {
						code := publicurlusagev1.BatchProblemCodeNotFound
						results[i].Code = &code
					}
				}
				_ = json.NewEncoder(response).Encode(publicurlusagev1.PublicURLUsageBucketReportBatchResponse{Results: results})
			}))
			t.Cleanup(receiver.Close)
			store := &publicURLUsageStoreStub{work: work, completeErr: failure, retryErr: failure}
			worker := testWorker(t, store, receiver.URL, now)
			completedAt := now.Add(2 * time.Second)
			clockCalls := 0
			worker.now = func() time.Time {
				clockCalls++
				if clockCalls == 1 {
					return now
				}
				return completedAt
			}
			if found, err := worker.process(t.Context()); !found || !errors.Is(err, failure) {
				t.Fatalf("process = %v, %v", found, err)
			}
			if store.claimWorker != "public_url_usage_worker_test" || store.claimLimit != 32 || store.claimLease != 2*time.Minute || !store.claimAt.Equal(now) {
				t.Fatalf("claim = %#v", store)
			}
			if accepted {
				want := []completionCall{{work[0], completedAt}, {work[1], completedAt}}
				if !reflect.DeepEqual(store.completeCalls, want) || len(store.retryCalls) != 0 {
					t.Fatalf("completion = %#v, retries = %#v", store.completeCalls, store.retryCalls)
				}
			} else {
				want := []retryCall{{work[0], completedAt.Add(4 * time.Second), "not_found", completedAt}, {work[1], completedAt.Add(time.Minute), "not_found", completedAt}}
				if !reflect.DeepEqual(store.retryCalls, want) || len(store.completeCalls) != 0 {
					t.Fatalf("retries = %#v, completions = %#v", store.retryCalls, store.completeCalls)
				}
			}
		})
	}
}

func TestWorkerJoinsTransportAndRetryPersistenceFailures(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	work := []controlstate.PublicURLUsageDeliveryWork{
		testDeliveryWork(1, "usage_report_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", now),
		testDeliveryWork(2, "usage_report_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", now),
	}
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(receiver.Close)
	failure := errors.New("retry persistence failed")
	store := &publicURLUsageStoreStub{work: work, retryErr: failure}
	worker := testWorker(t, store, receiver.URL, now)
	if found, err := worker.process(t.Context()); !found || !errors.Is(err, failure) || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("process = %v, %v", found, err)
	}
	want := []retryCall{
		{work[0], now.Add(time.Second), "server.usage_delivery_failed", now},
		{work[1], now.Add(time.Second), "server.usage_delivery_failed", now},
	}
	if !reflect.DeepEqual(store.retryCalls, want) || len(store.completeCalls) != 0 {
		messages := make([]string, 0, len(store.retryCalls))
		for _, call := range store.retryCalls {
			messages = append(messages, call.message)
		}
		t.Fatalf("retry messages = %q; completions = %d", messages, len(store.completeCalls))
	}
}
