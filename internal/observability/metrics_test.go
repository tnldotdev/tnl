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
	metrics := New("standalone")
	metrics.SetRelayLeases("active", 3)
	metrics.AddRelayLeases("active", -1)
	metrics.SetPublisherConnections("ready", 2)
	metrics.AddPublisherConnections("ready", 1)
	metrics.SetIngressStreams(4)
	metrics.AddRelayStreams(2)
	metrics.IncCapacityRejection("route_connections")
	metrics.IncSourceLimiterRejection()
	metrics.SetSourceLimiterEntries(5)
	metrics.IncIPAllowlistDenial()
	metrics.AddForwardedBytes("visitor_to_publisher", 1024)
	metrics.ObserveControlRequest("routes.create", "success", 10*time.Millisecond)
	metrics.ObserveRoutingHistoryFloor(100)
	metrics.ObserveRoutingHistoryFloor(50)
	metrics.ObserveRoutingHistoryBatch(0, 0, true)

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
		"tnl_routing_history_cleanup_skipped_total":   {kind: "COUNTER", value: 1},
		"tnl_routing_history_retained_after_revision": {kind: "GAUGE", value: 100},
		"tnl_info":                             {"GAUGE", map[string]string{"role": "standalone"}, 1},
		"tnl_relay_leases":                     {"GAUGE", map[string]string{"state": "active"}, 2},
		"tnl_publisher_connections":            {"GAUGE", map[string]string{"state": "ready"}, 3},
		"tnl_streams_active":                   {kind: "GAUGE"},
		"tnl_capacity_rejections_total":        {"COUNTER", map[string]string{"resource": "route_connections"}, 1},
		"tnl_source_limiter_rejections_total":  {kind: "COUNTER", value: 1},
		"tnl_source_limiter_entries":           {kind: "GAUGE", value: 5},
		"tnl_ip_allowlist_denials_total":       {kind: "COUNTER", value: 1},
		"tnl_forwarded_bytes_total":            {"COUNTER", map[string]string{"direction": "visitor_to_publisher"}, 1024},
		"tnl_control_requests_total":           {"COUNTER", map[string]string{"operation": "routes.create", "outcome": "success"}, 1},
		"tnl_control_request_duration_seconds": {"HISTOGRAM", map[string]string{"operation": "routes.create", "outcome": "success"}, 0.01},
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
		if name == "tnl_streams_active" {
			if family.GetType().String() != expected.kind || len(family.Metric) != 2 {
				t.Errorf("%s: type=%v samples=%d", name, family.GetType(), len(family.Metric))
				continue
			}
			values := make(map[string]float64)
			for _, metric := range family.Metric {
				if len(metric.Label) != 1 || metric.Label[0].GetName() != "stage" {
					t.Errorf("%s: labels=%v", name, metric.Label)
					continue
				}
				values[metric.Label[0].GetValue()] = metric.GetGauge().GetValue()
			}
			if !reflect.DeepEqual(values, map[string]float64{"ingress": 4, "relay": 2}) {
				t.Errorf("%s: values=%v", name, values)
			}
			continue
		}
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
			bounds := DurationBucketsSeconds()
			if histogram.GetSampleCount() != 1 || len(histogram.Bucket) != len(bounds) {
				t.Errorf("%s: histogram=%v", name, histogram)
				continue
			}
			for index, bucket := range histogram.Bucket {
				count := uint64(1)
				if bucket.GetUpperBound() < expected.value {
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

func TestMetricsExposeOnlyApplicableRoleFamilies(t *testing.T) {
	for _, test := range []struct {
		role string
		want []string
	}{
		{role: "control", want: []string{
			"tnl_routing_history_cleanup_rows_total", "tnl_routing_history_cleanup_skipped_total", "tnl_routing_history_retained_after_revision",
			"tnl_info", "tnl_control_requests_total", "tnl_control_request_duration_seconds",
		}},
		{role: "ingress", want: []string{
			"tnl_info", "tnl_streams_active", "tnl_capacity_rejections_total",
			"tnl_source_limiter_rejections_total", "tnl_source_limiter_entries",
			"tnl_ip_allowlist_denials_total", "tnl_forwarded_bytes_total",
		}},
		{role: "relay", want: []string{
			"tnl_info", "tnl_relay_leases", "tnl_publisher_connections",
			"tnl_streams_active", "tnl_capacity_rejections_total",
		}},
		{role: "standalone", want: []string{
			"tnl_routing_history_cleanup_rows_total", "tnl_routing_history_cleanup_skipped_total", "tnl_routing_history_retained_after_revision",
			"tnl_info", "tnl_control_requests_total", "tnl_control_request_duration_seconds",
			"tnl_relay_leases", "tnl_publisher_connections", "tnl_streams_active",
			"tnl_capacity_rejections_total", "tnl_source_limiter_rejections_total",
			"tnl_source_limiter_entries", "tnl_ip_allowlist_denials_total", "tnl_forwarded_bytes_total",
		}},
	} {
		t.Run(test.role, func(t *testing.T) {
			metrics := New(test.role)
			metrics.SetRelayLeases("active", 1)
			metrics.SetPublisherConnections("ready", 1)
			metrics.SetIngressStreams(1)
			metrics.AddRelayStreams(1)
			metrics.IncCapacityRejection("test")
			metrics.IncSourceLimiterRejection()
			metrics.SetSourceLimiterEntries(1)
			metrics.IncIPAllowlistDenial()
			metrics.AddForwardedBytes("visitor_to_publisher", 1)
			metrics.ObserveControlRequest("test", "success", time.Millisecond)
			metrics.ObserveRoutingHistoryBatch(2, 1, false)
			families, err := metrics.registry.Gather()
			if err != nil {
				t.Fatal(err)
			}
			want := make(map[string]bool, len(test.want))
			for _, name := range test.want {
				want[name] = true
			}
			for _, family := range families {
				name := family.GetName()
				if !strings.HasPrefix(name, "tnl_") {
					continue
				}
				if !want[name] {
					t.Errorf("unexpected %s metric %q", test.role, name)
				}
				delete(want, name)
			}
			for name := range want {
				t.Errorf("missing %s metric %q", test.role, name)
			}
		})
	}
}
