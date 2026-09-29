package observability

import (
	"compress/gzip"
	"io"
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

func TestPrivateCPUProfileIsBounded(t *testing.T) {
	handler := ProcessHandler(New("relay").Handler(), nil)
	for _, path := range []string{
		"/debug/pprof/profile?seconds=0", "/debug/pprof/profile?seconds=31",
		"/debug/pprof/profile?seconds=invalid", "/debug/pprof/profile?seconds=1&seconds=2",
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusBadRequest {
			t.Errorf("GET %s status = %d, want 400", path, response.Code)
		}
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/debug/pprof/cmdline", nil))
	if response.Code != http.StatusNotFound {
		t.Errorf("unexpected debug handler status = %d", response.Code)
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/debug/pprof/profile?seconds=1", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("CPU profile status = %d: %s", response.Code, response.Body.String())
	}
	compressed, err := gzip.NewReader(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := io.ReadAll(compressed)
	if err != nil || len(profile) == 0 {
		t.Fatalf("empty or invalid CPU profile: size=%d error=%v", len(profile), err)
	}
}

func TestReadinessAndRelayMetricsKeepFixedLabels(t *testing.T) {
	control := New("control")
	control.ObservePublishRunReadiness("publish_run_secret", time.Millisecond, 45*time.Second)
	control.ObserveCertificateWork("challenge_token_secret", "error_secret", time.Millisecond)
	control.ObserveCertificateMilestone("challenge_token_secret", time.Second)
	control.ObserveCertificateMilestone("ready", 30*time.Second)
	control.ObserveCertificateMilestone("cleanup", 45*time.Second)
	ingress := New("ingress")
	ingress.ObserveRelayAttempt("relay_address_secret", "error_secret")
	ingress.IncInspectionFailure("challenge_token_secret")
	ingress.IncChallengeRejection("challenge_token_secret")
	for _, metrics := range []*Metrics{control, ingress} {
		response := httptest.NewRecorder()
		metrics.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		body := response.Body.String()
		if response.Code != http.StatusOK || strings.Contains(body, "secret") {
			t.Fatalf("unbounded diagnostic labels: status=%d body=%s", response.Code, body)
		}
		if metrics == control && (!strings.Contains(body, `tnl_control_publish_run_readiness_duration_seconds_count{outcome="error"} 1`) ||
			!strings.Contains(body, `tnl_control_certificate_work_duration_seconds_count{kind="public_url",outcome="retry",stage="other"} 1`) ||
			!strings.Contains(body, `tnl_control_public_url_certificate_milestone_age_seconds_count{milestone="ready"} 1`) ||
			!strings.Contains(body, `tnl_control_public_url_certificate_milestone_age_seconds_count{milestone="cleanup"} 1`)) {
			t.Fatalf("missing bounded readiness or certificate outcomes: %s", body)
		}
		if metrics == ingress && !strings.Contains(body, `tnl_ingress_relay_attempts_total{connection_slot="unknown",outcome="other"} 1`) {
			t.Fatalf("missing bounded relay outcome: %s", body)
		}
	}
}

func TestMetricsExposeFinalRuntimeVocabulary(t *testing.T) {
	metrics := New("standalone")
	metrics.SetRelayLeases("active", 3)
	metrics.AddRelayLeases("active", -1)
	metrics.SetReadyPublisherConnections(2)
	metrics.AddReadyPublisherConnections(1)
	metrics.SetIngressStreams(4)
	metrics.AddRelayStreams(2)
	metrics.IncCapacityRejection("public_url_connections")
	metrics.IncInspectionFailure("client_hello")
	metrics.IncChallengeRejection("unavailable")
	metrics.ObserveVisitor("policy_denied")
	metrics.AddForwardedBytes("visitor_to_publisher", 1024)
	metrics.ObserveAPIRequest("control", "POST /v1/public-urls", "success", 10*time.Millisecond)
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
		"tnl_control_routing_history_cleanup_skipped_total":   {kind: "COUNTER", value: 1},
		"tnl_control_routing_history_retained_after_revision": {kind: "GAUGE", value: 100},
		"tnl_process_info":                         {"GAUGE", map[string]string{"role": "standalone"}, 1},
		"tnl_relay_local_leases":                   {"GAUGE", map[string]string{"state": "active"}, 2},
		"tnl_relay_publisher_connections_ready":    {kind: "GAUGE", value: 3},
		"tnl_ingress_backend_streams":              {kind: "GAUGE", value: 4},
		"tnl_relay_visitor_stream_slots_occupied":  {kind: "GAUGE", value: 2},
		"tnl_admission_rejections_total":           {"COUNTER", map[string]string{"resource": "public_url_connections"}, 1},
		"tnl_ingress_inspection_failures_total":    {"COUNTER", map[string]string{"stage": "client_hello"}, 1},
		"tnl_ingress_challenge_rejections_total":   {"COUNTER", map[string]string{"reason": "unavailable"}, 1},
		"tnl_ingress_visitor_connections_total":    {"COUNTER", map[string]string{"outcome": "policy_denied"}, 1},
		"tnl_ingress_forwarded_bytes_total":        {"COUNTER", map[string]string{"direction": "visitor_to_publisher"}, 1024},
		"tnl_control_api_request_duration_seconds": {"HISTOGRAM", map[string]string{"surface": "control", "operation": "POST /v1/public-urls", "outcome": "success"}, 0.01},
	}
	for _, family := range families {
		name := family.GetName()
		for _, retired := range []string{"gateway", "worker", "sqlite"} {
			if strings.Contains(name, retired) {
				t.Errorf("obsolete metric family %q", name)
			}
		}
		if !strings.HasPrefix(name, "tnl_") {
			continue
		}
		expected, ok := want[name]
		if !ok {
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

func TestMetricsExposeEffectiveCapacityLimits(t *testing.T) {
	metrics := New("ingress")
	metrics.SetCapacityLimit("public_connections", 101)
	metrics.SetCapacityLimit("public_url_connections", 50)
	response := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `tnl_admission_limit{resource="public_connections"} 101`) ||
		!strings.Contains(response.Body.String(), `tnl_admission_limit{resource="public_url_connections"} 50`) {
		t.Fatalf("effective limits missing: %s", response.Body.String())
	}
}

func TestMetricsExposeOnlyApplicableRoleFamilies(t *testing.T) {
	for _, test := range []struct {
		role string
		want []string
	}{
		{role: "control", want: []string{
			"tnl_control_routing_history_cleanup_rows_total", "tnl_control_routing_history_cleanup_skipped_total", "tnl_control_routing_history_retained_after_revision",
			"tnl_process_info", "tnl_control_api_request_duration_seconds",
		}},
		{role: "ingress", want: []string{
			"tnl_process_info", "tnl_ingress_backend_streams", "tnl_admission_rejections_total",
			"tnl_ingress_visitor_connections_total", "tnl_ingress_forwarded_bytes_total",
		}},
		{role: "relay", want: []string{
			"tnl_process_info", "tnl_relay_local_leases", "tnl_relay_publisher_connections_ready",
			"tnl_relay_visitor_stream_slots_occupied", "tnl_admission_rejections_total",
		}},
		{role: "standalone", want: []string{
			"tnl_control_routing_history_cleanup_rows_total", "tnl_control_routing_history_cleanup_skipped_total", "tnl_control_routing_history_retained_after_revision",
			"tnl_process_info", "tnl_control_api_request_duration_seconds",
			"tnl_relay_local_leases", "tnl_relay_publisher_connections_ready", "tnl_ingress_backend_streams", "tnl_relay_visitor_stream_slots_occupied",
			"tnl_admission_rejections_total", "tnl_ingress_visitor_connections_total", "tnl_ingress_forwarded_bytes_total",
		}},
	} {
		t.Run(test.role, func(t *testing.T) {
			metrics := New(test.role)
			metrics.SetRelayLeases("active", 1)
			metrics.SetReadyPublisherConnections(1)
			metrics.SetIngressStreams(1)
			metrics.AddRelayStreams(1)
			metrics.IncCapacityRejection("test")
			metrics.ObserveVisitor("policy_denied")
			metrics.AddForwardedBytes("visitor_to_publisher", 1)
			metrics.ObserveAPIRequest("control", "GET /test", "success", time.Millisecond)
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
				if test.role != "standalone" && (test.role != "control" && strings.HasPrefix(name, "tnl_control_") ||
					test.role != "ingress" && strings.HasPrefix(name, "tnl_ingress_") ||
					test.role != "relay" && strings.HasPrefix(name, "tnl_relay_")) {
					t.Errorf("%s exposes another role's metric %q", test.role, name)
				}
				if !want[name] {
					continue
				}
				delete(want, name)
			}
			for name := range want {
				t.Errorf("missing %s metric %q", test.role, name)
			}
		})
	}
}
