package observability

import (
	"io"
	"net/http"
	"net/http/httptest"
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
	metrics.SetPublisherConnections("ready", 2)
	metrics.SetStreams(4)
	metrics.IncCapacityRejection("route_connections")
	metrics.IncSourceLimiterRejection()
	metrics.SetSourceLimiterEntries(5)
	metrics.IncIPAllowlistDenial()
	metrics.AddForwardedBytes("visitor_to_publisher", 1024)
	metrics.ObserveControlRequest("routes.create", "success", 10*time.Millisecond)

	request := httptest.NewRequest("GET", "/metrics", nil)
	response := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(response, request)
	body, err := io.ReadAll(response.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, value := range []string{
		`tnl_info{mode="relay"} 1`, `tnl_routes{state="enabled"} 7`, `tnl_relay_leases{state="active"} 3`,
		`tnl_publisher_connections{state="ready"} 2`, `tnl_streams_active 4`,
		`tnl_forwarded_bytes_total{direction="visitor_to_publisher"} 1024`,
		`tnl_control_requests_total{operation="routes.create",outcome="success"} 1`,
	} {
		if !strings.Contains(text, value) {
			t.Errorf("metrics output does not contain %q", value)
		}
	}
	if strings.Contains(text, "gateway") || strings.Contains(text, "tailcat") || strings.Contains(text, "worker") || strings.Contains(text, "sqlite") {
		t.Fatal("metrics retained obsolete runtime vocabulary")
	}
}
