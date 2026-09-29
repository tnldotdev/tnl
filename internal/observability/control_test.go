package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestControlRequestDurationOutcomes(t *testing.T) {
	metrics := New("control")
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	expired, stop := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer stop()
	for _, test := range []struct {
		ctx    context.Context
		status int
	}{
		{t.Context(), 204}, {t.Context(), 400}, {t.Context(), 503},
		{canceled, 204}, {expired, 204},
	} {
		mux := http.NewServeMux()
		mux.Handle("GET /test/{id}", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(test.status)
		}))
		metrics.APIRequests("control", mux).ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(test.ctx, "GET", "/test/private-id", nil))
	}
	families, err := metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"success": true, "client_error": true, "server_error": true, "canceled": true, "deadline_exceeded": true}
	for _, family := range families {
		if family.GetName() != "tnl_control_api_request_duration_seconds" {
			continue
		}
		for _, metric := range family.Metric {
			labels := make(map[string]string)
			for _, label := range metric.Label {
				labels[label.GetName()] = label.GetValue()
			}
			if len(labels) != 3 || labels["surface"] != "control" || labels["operation"] != "GET /test/{id}" || !want[labels["outcome"]] {
				t.Fatalf("unexpected labels: %v", labels)
			}
			if metric.GetHistogram().GetSampleCount() != 1 || metric.GetHistogram().GetSampleSum() <= 0 {
				t.Fatalf("handler not timed: %v", metric)
			}
			delete(want, labels["outcome"])
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing HTTP outcomes: %v", want)
	}
}

func TestAPIRequestsCountPreAuthenticationFailuresWithMatchedPattern(t *testing.T) {
	metrics := New("control")
	request := httptest.NewRequest(http.MethodPost, "/internal/v1/relays/private-relay-id/renew", nil)
	request.Pattern = "POST /internal/v1/relays/{relay_id}/renew"
	metrics.APIRequests("private_relay", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})).ServeHTTP(httptest.NewRecorder(), request)
	response := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	text := response.Body.String()
	if strings.Contains(text, "private-relay-id") || !strings.Contains(text,
		`tnl_control_api_request_duration_seconds_count{operation="POST /internal/v1/relays/{relay_id}/renew",outcome="client_error",surface="private_relay"} 1`) {
		t.Fatalf("private request metric omitted matched pattern or leaked an ID: %s", text)
	}
}
