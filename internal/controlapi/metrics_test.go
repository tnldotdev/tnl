package controlapi

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/observability"
)

func TestControlHandlersRecordMatchedOperations(t *testing.T) {
	metrics := observability.New("control")
	handler := testHandler(t, Config{Metrics: metrics}, nil, nil, nil)
	observed := metrics.APIRequests("control", handler)
	for _, path := range []string{"/v1/health", "/v1/public-urls/public_url_private-id"} {
		observed.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", path, nil))
	}
	response := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	text := response.Body.String()
	if strings.Contains(text, "public_url_private-id") {
		t.Fatal("metrics exposed a route ID")
	}
	for _, want := range []string{"tnl_control_api_request_duration_seconds_count", "tnl_control_api_requests_in_flight", `outcome="client_error"`, `outcome="success"`} {
		if !strings.Contains(text, want) {
			t.Errorf("metrics missing %q:\n%s", want, text)
		}
	}
}
