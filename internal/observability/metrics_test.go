package observability

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestProcessHandlerHealthAndReadiness(t *testing.T) {
	ready := false
	handler := ProcessHandler(New("ingress").Handler(), func() bool { return ready })
	for _, test := range []struct {
		path       string
		wantStatus int
	}{
		{path: "/health", wantStatus: http.StatusNoContent},
		{path: "/ready", wantStatus: http.StatusServiceUnavailable},
		{path: "/metrics", wantStatus: http.StatusOK},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
		if response.Code != test.wantStatus {
			t.Errorf("GET %s status = %d, want %d", test.path, response.Code, test.wantStatus)
		}
	}
	ready = true
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/ready", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("ready status = %d", response.Code)
	}
}

func TestMetricsExposeFinalRuntimeVocabulary(t *testing.T) {
	metrics := New("relay")
	metrics.SetRoutes("enabled", 7)
	metrics.SetRelayLeases("active", 3)
	metrics.AddRelayLeases("active", -1)
	metrics.SetPublisherConnections("ready", 2)
	metrics.AddPublisherConnections("ready", 1)
	metrics.SetStreams(4)
	metrics.IncCapacityRejection("route_connections")
	metrics.IncSourceLimiterRejection()
	metrics.SetSourceLimiterEntries(5)
	metrics.IncIPAllowlistDenial()
	metrics.AddForwardedBytes("visitor_to_publisher", 1024)
	metrics.ObserveControlRequest("routes.create", "success", 10*time.Millisecond)

	families, err := metrics.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	type sample struct {
		kind   string
		labels map[string]string
		value  float64
	}
	want := map[string]sample{
		"tnl_info":                             {"GAUGE", map[string]string{"role": "relay"}, 1},
		"tnl_routes":                           {"GAUGE", map[string]string{"state": "enabled"}, 7},
		"tnl_relay_leases":                     {"GAUGE", map[string]string{"state": "active"}, 2},
		"tnl_publisher_connections":            {"GAUGE", map[string]string{"state": "ready"}, 3},
		"tnl_streams_active":                   {kind: "GAUGE", value: 4},
		"tnl_capacity_rejections_total":        {"COUNTER", map[string]string{"resource": "route_connections"}, 1},
		"tnl_source_limiter_rejections_total":  {kind: "COUNTER", value: 1},
		"tnl_source_limiter_entries":           {kind: "GAUGE", value: 5},
		"tnl_ip_allowlist_denials_total":       {kind: "COUNTER", value: 1},
		"tnl_forwarded_bytes_total":            {"COUNTER", map[string]string{"direction": "visitor_to_publisher"}, 1024},
		"tnl_control_requests_total":           {"COUNTER", map[string]string{"operation": "routes.create", "outcome": "success"}, 1},
		"tnl_control_request_duration_seconds": {"HISTOGRAM", map[string]string{"operation": "routes.create"}, 0.01},
	}
	for _, family := range families {
		name := family.GetName()
		for _, retired := range []string{"gateway", "tailcat", "worker", "sqlite"} {
			if strings.Contains(name, retired) {
				t.Errorf("obsolete metric family %q", name)
			}
		}
		if !strings.HasPrefix(name, "tnl_") {
			continue
		}
		expected, ok := want[name]
		if !ok {
			t.Errorf("unexpected application metric %q", name)
			continue
		}
		delete(want, name)
		if family.GetType().String() != expected.kind || len(family.Metric) != 1 {
			t.Errorf("%s: type=%v samples=%d", name, family.GetType(), len(family.Metric))
			continue
		}
		metric := family.Metric[0]
		var labels map[string]string
		if len(metric.Label) != 0 {
			labels = make(map[string]string)
		}
		for _, label := range metric.Label {
			labels[label.GetName()] = label.GetValue()
		}
		if !reflect.DeepEqual(labels, expected.labels) || len(metric.Label) != len(expected.labels) {
			t.Errorf("%s: labels=%v, want %v", name, labels, expected.labels)
		}
		var value float64
		switch expected.kind {
		case "GAUGE":
			value = metric.GetGauge().GetValue()
		case "COUNTER":
			value = metric.GetCounter().GetValue()
		case "HISTOGRAM":
			histogram := metric.GetHistogram()
			value = histogram.GetSampleSum()
			bounds := []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
			if histogram.GetSampleCount() != 1 || len(histogram.Bucket) != len(bounds) {
				t.Errorf("%s: histogram=%v", name, histogram)
				continue
			}
			for index, bucket := range histogram.Bucket {
				count := uint64(1)
				if index == 0 {
					count = 0
				}
				if bucket.GetUpperBound() != bounds[index] || bucket.GetCumulativeCount() != count {
					t.Errorf("%s: bucket %d = %v", name, index, bucket)
				}
			}
		}
		if value != expected.value {
			t.Errorf("%s: value=%v, want %v", name, value, expected.value)
		}
	}
	for name := range want {
		t.Errorf("missing application metric %q", name)
	}
}
