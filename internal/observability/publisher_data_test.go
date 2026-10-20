package observability

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func dataMetric(t *testing.T, m *Metrics, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := ParseMetrics(strings.NewReader(metricsText(t, m)))
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, point := range family.Metric {
			matched := true
			for key, value := range labels {
				found := false
				for _, label := range point.Label {
					if label.GetName() == key && label.GetValue() == value {
						found = true
					}
				}
				if !found {
					matched = false
				}
			}
			if matched {
				if point.Gauge != nil {
					return point.Gauge.GetValue()
				}
				if point.Counter != nil {
					return point.Counter.GetValue()
				}
				if point.Histogram != nil {
					return float64(point.Histogram.GetSampleCount())
				}
			}
		}
	}
	return 0
}

func TestPublisherHTTPObservesLiveStreamingAndSafeFinalResult(t *testing.T) {
	m := New("publisher")
	defer m.Shutdown(context.Background())
	exporter := tracetest.NewInMemoryExporter()
	m.tracerProvider = sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	ctx := WithMetrics(t.Context(), m)
	ctx = ReplaceIdentity(ctx, Identity{TeamID: "team", DeploymentID: "deployment", PublicURLID: "url"})
	ctx = WithFields(ctx, Fields{Component: "publisher", ServiceProtocol: "http", AccessPath: "direct", Exposure: "public"})
	request := httptest.NewRequest("CUSTOM-SECRET", "/secret-path?password=secret", strings.NewReader("secret request payload")).WithContext(ctx)
	request.Header.Set("Traceparent", "customer-owned")
	response := httptest.NewRecorder()
	PublisherHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Traceparent") != "customer-owned" {
			t.Fatal("customer header changed")
		}
		PublisherHTTPForward(r.Context())
		_, _ = io.Copy(io.Discard, r.Body)
		PublisherHTTPResponse(r.Context())
		w.WriteHeader(503)
		_, _ = w.Write([]byte("secret response payload"))
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Fatal(err)
		}
		if got := dataMetric(t, m, "tnl_publisher_http_requests_active", nil); got != 1 {
			t.Fatal("stream not active", got)
		}
		if got := dataMetric(t, m, "tnl_publisher_forwarded_bytes_total", map[string]string{"tnl_direction": "target_to_visitor"}); got != float64(len("secret response payload")) {
			t.Fatal("bytes delayed until completion", got)
		}
		if got := dataMetric(t, m, "tnl_publisher_http_request_duration_seconds", nil); got != 0 {
			t.Fatal("stream completed early", got)
		}
	})).ServeHTTP(response, request)
	if got := dataMetric(t, m, "tnl_publisher_http_requests_active", nil); got != 0 {
		t.Fatal("active request leaked", got)
	}
	labels := map[string]string{"http_request_method": "_OTHER", "http_response_status_code": "503", "tnl_response_origin": "local_service", "tnl_outcome": "error", "tnl_deployment_id": "deployment"}
	if got := dataMetric(t, m, "tnl_publisher_http_request_duration_seconds", labels); got != 1 {
		t.Fatal("missing classified completion", metricsText(t, m))
	}
	if got := dataMetric(t, m, "tnl_publisher_http_response_headers_duration_seconds", labels); got != 1 {
		t.Fatal("missing final headers timing")
	}
	spans := exporter.GetSpans()
	if len(spans) != 1 || !containsAttribute(spans[0].Attributes, string(OutcomeKey), "error") {
		t.Fatal(spans)
	}
	if strings.Contains(metricsText(t, m)+fmt.Sprint(spans), "secret") || strings.Contains(fmt.Sprint(spans), "customer-owned") {
		t.Fatal("customer data exported")
	}
}

func TestPublisherAuthorizationKeepsPendingDenialAndFailureDistinct(t *testing.T) {
	m := New("publisher")
	defer m.Shutdown(context.Background())
	exporter := tracetest.NewInMemoryExporter()
	m.tracerProvider = sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	ctx := WithMetrics(t.Context(), m)
	cause := errors.New("secret provider response")
	err := failure.Wrap("authorize visitor", failure.TargetUnavailable, cause)
	PublisherAuthorization(ctx, true, false, nil)
	PublisherAuthorization(ctx, true, true, nil)
	PublisherAuthorization(ctx, false, false, nil)
	PublisherAuthorization(ctx, false, false, err)
	for state, outcome := range map[string]string{"pending": "success", "admitted": "success", "denied": "denied", "failed": "error"} {
		if got := dataMetric(t, m, "tnl_publisher_authorization_decisions_total", map[string]string{"tnl_state": state, "tnl_outcome": outcome}); got != 1 {
			t.Fatal(state, got, metricsText(t, m))
		}
	}
	if !errors.Is(err, cause) || strings.Contains(fmt.Sprint(exporter.GetSpans()), "secret") {
		t.Fatal("cause lost or leaked")
	}
}

func TestPublisherStreamRecordsIncrementallyAndFinishesOnce(t *testing.T) {
	m := New("publisher")
	defer m.Shutdown(context.Background())
	ctx, cancel := context.WithCancel(WithMetrics(t.Context(), m))
	defer cancel()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	observed, finish := PublisherStream(ctx, left)
	done := make(chan error, 1)
	go func() { _, err := right.Write([]byte("payload")); done <- err }()
	buffer := make([]byte, 7)
	if _, err := io.ReadFull(observed, buffer); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := dataMetric(t, m, "tnl_publisher_visitor_streams_active", nil); got != 1 {
		t.Fatal(got)
	}
	if got := dataMetric(t, m, "tnl_publisher_forwarded_bytes_total", map[string]string{"tnl_direction": "target_to_visitor"}); got != 7 {
		t.Fatal(got)
	}
	cancel()
	finish(net.ErrClosed)
	finish(nil)
	if got := dataMetric(t, m, "tnl_publisher_visitor_streams_active", nil); got != 0 {
		t.Fatal(got)
	}
	if got := dataMetric(t, m, "tnl_publisher_visitor_stream_completions_total", map[string]string{"tnl_outcome": "canceled"}); got != 1 {
		t.Fatal(got)
	}
}

func TestPublisherTLSRecordsNegotiatedFactsAndNoFactsOnFailure(t *testing.T) {
	m := New("publisher")
	defer m.Shutdown(context.Background())
	ctx := WithMetrics(t.Context(), m)
	state := tls.ConnectionState{Version: tls.VersionTLS13, DidResume: true, ServerName: "secret.example"}
	PublisherTLS(ctx, "target", state, nil)
	PublisherTLS(ctx, "visitor", state, context.DeadlineExceeded)
	if got := dataMetric(t, m, "tnl_publisher_tls_handshakes_total", map[string]string{"tnl_tls_leg": "target", "tls_protocol_version": "1.3", "tls_resumed": "true", "tnl_outcome": "success"}); got != 1 {
		t.Fatal(metricsText(t, m))
	}
	if got := dataMetric(t, m, "tnl_publisher_tls_handshakes_total", map[string]string{"tnl_tls_leg": "visitor", "tls_protocol_version": "1.3"}); got != 0 {
		t.Fatal("failed TLS exported negotiated state")
	}
	if strings.Contains(metricsText(t, m), "secret.example") {
		t.Fatal("TLS peer exported")
	}
}

func TestPublisherGeneratedResponseDoesNotCountAsTargetTrafficOrRecovery(t *testing.T) {
	m := New("publisher")
	defer m.Shutdown(context.Background())
	ctx := WithPublisherRecovery(WithMetrics(t.Context(), m))
	closed := PublisherConnectionLifetime(ctx, "quic", 0)
	closed(errors.New("fixture carrier lost"), false)
	request := httptest.NewRequest("POST", "/", strings.NewReader("publisher-owned request")).WithContext(ctx)
	PublisherHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(403)
		_, _ = io.WriteString(w, "publisher-owned response")
	})).ServeHTTP(httptest.NewRecorder(), request)
	if dataMetric(t, m, "tnl_publisher_forwarded_bytes_total", nil) != 0 || dataMetric(t, m, "tnl_publisher_recovery_duration_seconds", nil) != 0 {
		t.Fatal("publisher-owned response pretended to reach the target")
	}
	// a successful target response without a body still proves response progress.
	PublisherHTTP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		PublisherHTTPResponse(r.Context())
		w.WriteHeader(204)
	})).ServeHTTP(httptest.NewRecorder(), request)
	if dataMetric(t, m, "tnl_publisher_recovery_duration_seconds", nil) != 1 || dataMetric(t, m, "tnl_publisher_forwarded_bytes_total", nil) != 0 {
		t.Fatal("header-only target response did not close recovery without inventing body bytes")
	}
}

func TestPublisherConnectionRedundancyAndRecoveryStayRunLocal(t *testing.T) {
	m := New("publisher")
	defer m.Shutdown(context.Background())
	ctx := WithPublisherRecovery(WithMetrics(t.Context(), m))
	other := WithPublisherRecovery(WithMetrics(t.Context(), m))
	endFirst := PublisherConnectionLifetime(ctx, "quic", 0)
	endSecond := PublisherConnectionLifetime(ctx, "tls-tcp", 1)
	if got := dataMetric(t, m, "tnl_publisher_connections_active", map[string]string{"tnl_connection_slot": "0"}); got != 1 {
		t.Fatal(got)
	}
	endFirst(errors.New("secret connection error"), false)
	endFirst(nil, true)
	if got := dataMetric(t, m, "tnl_publisher_connections_active", map[string]string{"tnl_connection_slot": "0"}); got != 0 {
		t.Fatal("connection occupancy leaked", got)
	}
	if got := dataMetric(t, m, "tnl_publisher_connections_active", map[string]string{"tnl_connection_slot": "1"}); got != 1 {
		t.Fatal("healthy slot lost", got)
	}
	publisherBytes(other, "target_to_visitor", 1)
	if got := dataMetric(t, m, "tnl_publisher_recovery_duration_seconds", nil); got != 0 {
		t.Fatal("another run closed recovery", got)
	}
	publisherBytes(ctx, "visitor_to_target", 1)
	if got := dataMetric(t, m, "tnl_publisher_recovery_duration_seconds", nil); got != 0 {
		t.Fatal("visitor bytes closed recovery", got)
	}
	publisherBytes(ctx, "target_to_visitor", 1)
	publisherBytes(ctx, "target_to_visitor", 1)
	if got := dataMetric(t, m, "tnl_publisher_recovery_duration_seconds", nil); got != 1 {
		t.Fatal("recovery not completed exactly once", got)
	}
	endSecond(context.Canceled, true)
	if got := dataMetric(t, m, "tnl_publisher_connection_events_total", map[string]string{"tnl_event": "expected_close", "tnl_outcome": "success"}); got != 1 {
		t.Fatal(metricsText(t, m))
	}
	if strings.Contains(metricsText(t, m), "secret") {
		t.Fatal("connection error leaked")
	}
}

func TestPublisherHTTPAbortKeepsCancellationAndReleasesOccupancy(t *testing.T) {
	m := New("publisher")
	defer m.Shutdown(context.Background())
	ctx, cancel := context.WithCancel(WithMetrics(t.Context(), m))
	request := httptest.NewRequest("GET", "/private", nil).WithContext(ctx)
	func() {
		defer func() {
			if got := recover(); got != http.ErrAbortHandler {
				t.Fatal("abort changed", got)
			}
		}()
		PublisherHTTP(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { cancel(); panic(http.ErrAbortHandler) })).ServeHTTP(httptest.NewRecorder(), request)
	}()
	if got := dataMetric(t, m, "tnl_publisher_http_requests_active", nil); got != 0 {
		t.Fatal("aborted handler leaked", got)
	}
	if got := dataMetric(t, m, "tnl_publisher_http_request_duration_seconds", map[string]string{"tnl_outcome": "canceled"}); got != 1 {
		t.Fatal(metricsText(t, m))
	}
}
