package publisher

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/inspection"
	"github.com/tnldotdev/tnl/internal/observability"
)

func TestRequestObservationSeparatesLocalAndPublisherResponses(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/broken" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	var events []inspection.Summary
	server, err := newTestPublicURLServer(PublicURLServerConfig{
		Hostname: "app.example", Target: upstream.URL,
		ObserveSummary: func(event inspection.Summary) { events = append(events, event) },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, test := range []struct {
		path   string
		status int
		origin string
	}{
		{"/ok?token=private", 204, "local_service"},
		{"/broken", 500, "local_service"},
		{"/invalid", 400, "tnl"},
	} {
		request := httptest.NewRequest(http.MethodGet, test.path, nil)
		request.Host = "app.example"
		request.TLS = &tls.ConnectionState{ServerName: "app.example"}
		if test.path == "/invalid" {
			request.Host = "other.example"
		}
		response := httptest.NewRecorder()
		server.http.Handler.ServeHTTP(response, request)
		if response.Code != test.status {
			t.Fatalf("%s: status = %d", test.path, response.Code)
		}
	}
	if len(events) != 3 {
		t.Fatalf("observations = %+v", events)
	}
	for i, want := range []struct {
		path   string
		status int
		origin string
	}{
		{"/ok", 204, "local_service"}, {"/broken", 500, "local_service"}, {"/invalid", 400, "tnl"},
	} {
		got := events[i]
		if got.Path != want.path || got.Status != want.status || got.Origin != want.origin || got.Method != http.MethodGet ||
			got.ReceivedAt.IsZero() || got.Duration < 0 || got.Duration > time.Minute {
			t.Fatalf("observation %d = %+v", i, got)
		}
	}
}

func TestRequestObservationNoneRecordsNothing(t *testing.T) {
	metrics := observability.New("publisher")
	defer metrics.Shutdown(context.Background())
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	observed := 0
	server, err := newTestPublicURLServer(PublicURLServerConfig{Hostname: "app.example", Target: upstream.URL,
		InspectionMode: inspection.None, ObserveSummary: func(inspection.Summary) { observed++ }})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	request := httptest.NewRequest(http.MethodGet, "/health?token=private", nil)
	request = request.WithContext(observability.WithMetrics(request.Context(), metrics))
	request.Host = "app.example"
	request.TLS = &tls.ConnectionState{ServerName: "app.example"}
	response := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || observed != 0 {
		t.Fatalf("none mode response = %d, observations = %d", response.Code, observed)
	}
	scrape := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(scrape, httptest.NewRequest("GET", "/metrics", nil))
	text := scrape.Body.String()
	if !strings.Contains(text, "tnl_publisher_http_request_duration_seconds_count") || !strings.Contains(text, `tnl_response_origin="local_service"`) || strings.Contains(text, "token=private") || strings.Contains(text, "/health") {
		t.Fatal("inspection none must retain safe OTel request measurements", text)
	}
	if _, err := NewPublicURLServer(PublicURLServerConfig{Hostname: "app.example", Target: upstream.URL,
		InspectionMode: "detailed"}); err == nil {
		t.Fatal("detailed inspection mode was accepted")
	}
}
