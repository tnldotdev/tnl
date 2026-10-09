package controlapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/observability"
)

func TestWebhookProviderSourcesAreCachedAndMeasuredWithoutURLs(t *testing.T) {
	metrics := observability.New("control")
	handler := testHandler(t, Config{Metrics: metrics}, nil, nil, func(context.Context) error { return nil })
	request := func(provider string, etag string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		visitor := httptest.NewRequest(http.MethodGet, "/v1/webhook-providers/"+provider+"/source", nil)
		if etag != "" {
			visitor.Header.Set("If-None-Match", etag)
		}
		handler.ServeHTTP(response, visitor)
		return response
	}
	first := request("resend", "")
	var body struct {
		Source struct {
			Kind   string   `json:"kind"`
			Ranges []string `json:"ranges"`
		} `json:"source"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &body); err != nil || first.Code != http.StatusOK || body.Source.Kind != "ip_ranges" ||
		len(body.Source.Ranges) != 5 || first.Header().Get("Cache-Control") != "public, max-age=900" || first.Header().Get("ETag") == "" {
		t.Fatalf("provider response = %d, source=%+v, error=%v", first.Code, body.Source, err)
	}
	notModified := request("resend", first.Header().Get("ETag"))
	if notModified.Code != http.StatusNotModified || notModified.Body.Len() != 0 || notModified.Header().Get("ETag") != first.Header().Get("ETag") {
		t.Fatalf("conditional response = %d, %q", notModified.Code, notModified.Body.String())
	}
	unknown := request("svix", "")
	if unknown.Code != http.StatusNotFound || unknown.Header().Get("Cache-Control") == "public, max-age=900" {
		t.Fatalf("unknown provider response = %d", unknown.Code)
	}
	metric := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(metric, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, expected := range []string{
		`tnl_control_webhook_provider_source_requests_total{outcome="served",provider="resend"} 1`,
		`tnl_control_webhook_provider_source_requests_total{outcome="not_modified",provider="resend"} 1`,
		`tnl_control_webhook_provider_source_requests_total{outcome="unknown",provider="unknown"} 1`,
	} {
		if !strings.Contains(metric.Body.String(), expected) {
			t.Errorf("missing bounded metric %q", expected)
		}
	}
	if strings.Contains(metric.Body.String(), "svix") {
		t.Fatal("unbounded provider value entered metric labels")
	}
}
