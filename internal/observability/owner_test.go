package observability

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"
)

func TestExportConfigurationRequiresExplicitHTTPSAndKeepsSecretsOutOfErrors(t *testing.T) {
	get := func(values map[string]string) func(string) string {
		return func(key string) string { return values[key] }
	}
	c, err := ConfigFromEnv(get(nil))
	if err != nil || c.Metrics.Endpoint != "" || c.Traces.Endpoint != "" {
		t.Fatal(c, err)
	}
	values := map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector.invalid/base", "OTEL_EXPORTER_OTLP_HEADERS": "Authorization=Bearer%20secret", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "https://trace.invalid/custom", "OTEL_EXPORTER_OTLP_TRACES_HEADERS": "x-key=trace-secret", "OTEL_BSP_MAX_QUEUE_SIZE": "4"}
	c, err = ConfigFromEnv(get(values))
	if err != nil || c.Metrics.Endpoint != "https://collector.invalid/base/v1/metrics" || c.Traces.Endpoint != "https://trace.invalid/custom" || c.Metrics.Headers["Authorization"] != "Bearer secret" || c.Traces.Headers["x-key"] != "trace-secret" || c.BatchSize != 4 {
		t.Fatal("incorrect standard endpoint/header precedence", err)
	}
	if strings.Contains(fmt.Sprintf("%+v %#v %+v", c, c, c.Metrics), "secret") {
		t.Fatal("configuration formatting exposed credentials")
	}
	for key, value := range map[string]string{
		"OTEL_EXPORTER_OTLP_ENDPOINT":        "http://secret.invalid",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "https://user:secret@collector.invalid/v1/traces",
		"OTEL_EXPORTER_OTLP_PROTOCOL":        "grpc-secret",
		"OTEL_EXPORTER_OTLP_HEADERS":         "Authorization=secret%0d%0aevil",
		"OTEL_EXPORTER_OTLP_INSECURE":        "true-secret",
		"OTEL_EXPORTER_OTLP_TIMEOUT":         "999999-secret",
		"OTEL_BSP_MAX_QUEUE_SIZE":            "999999-secret",
		"OTEL_RESOURCE_ATTRIBUTES":           "request.id=secret",
		"OTEL_TRACES_SAMPLER":                "secret",
	} {
		t.Run(key, func(t *testing.T) {
			_, err := ConfigFromEnv(get(map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector.invalid", key: value}))
			if err == nil || strings.Contains(err.Error(), "secret") {
				t.Fatalf("unsafe or missing validation: %v", err)
			}
		})
	}
}

func TestOTLPHTTPSExportsSameInstrumentsAndRuntimeCompatibility(t *testing.T) {
	var mu sync.Mutex
	var metrics collectormetrics.ExportMetricsServiceRequest
	var traces collectortrace.ExportTraceServiceRequest
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer local-fixture-secret" {
			t.Error("missing configured export header")
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		var response proto.Message
		switch r.URL.Path {
		case "/v1/metrics":
			err = proto.Unmarshal(body, &metrics)
			response = &collectormetrics.ExportMetricsServiceResponse{}
		case "/v1/traces":
			err = proto.Unmarshal(body, &traces)
			response = &collectortrace.ExportTraceServiceResponse{}
		default:
			t.Error("unexpected export path", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		if err != nil {
			t.Error(err)
		}
		data, _ := proto.Marshal(response)
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(data)
	}))
	defer receiver.Close()
	signal := SignalConfig{Endpoint: receiver.URL + "/v1/metrics", Headers: map[string]string{"Authorization": "Bearer local-fixture-secret"}, Timeout: time.Second, TLS: receiver.Client().Transport.(*http.Transport).TLSClientConfig.Clone()}
	config := Config{Metrics: signal, Traces: signal, Interval: time.Hour, BatchDelay: time.Hour, SampleRatio: 1}
	config.Traces.Endpoint = receiver.URL + "/v1/traces"
	m, err := newOwner("standalone", config)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown(context.Background())
	ctx := WithMetrics(t.Context(), m)
	m.ObserveOperation("CreatePublishRun", nil, 25*time.Millisecond)
	_, finish := Start(ctx, "local.fixture")
	finish(errors.New("secret error body"))
	if err := m.ForceFlush(t.Context()); err != nil {
		t.Fatal(err)
	}
	families, err := m.Gather()
	if err != nil {
		t.Fatal(err)
	}
	summaries, err := DurationSummaries(nil, families)
	if err != nil || len(summaries) != 1 || summaries[0].Count != 1 || summaries[0].SumSeconds != .025 {
		t.Fatalf("scrape compatibility: %+v %v", summaries, err)
	}
	mu.Lock()
	defer mu.Unlock()
	seenDuration, seenRuntime, seenProcess, seenSpan := false, false, false, false
	for _, r := range metrics.ResourceMetrics {
		for _, s := range r.ScopeMetrics {
			for _, metric := range s.Metrics {
				switch metric.Name {
				case "tnl_control_operation_duration_seconds":
					points := metric.GetHistogram().GetDataPoints()
					if len(points) != 1 || points[0].Count != 1 || len(points[0].ExplicitBounds) != len(DurationBucketsSeconds()) {
						t.Fatalf("OTLP changed histogram: %v", metric)
					}
					for i, bound := range DurationBucketsSeconds() {
						if points[0].ExplicitBounds[i] != bound {
							t.Fatal("histogram bounds changed")
						}
					}
					seenDuration = true
				case "go_goroutines":
					seenRuntime = true
				case "process_start_time_seconds":
					seenProcess = true
				}
			}
		}
	}
	for _, r := range traces.ResourceSpans {
		for _, s := range r.ScopeSpans {
			for _, span := range s.Spans {
				if span.Name == "local.fixture" {
					seenSpan = true
				}
			}
		}
	}
	if !seenDuration || !seenRuntime || !seenProcess || !seenSpan {
		t.Fatalf("missing signals: histogram=%t runtime=%t process=%t span=%t", seenDuration, seenRuntime, seenProcess, seenSpan)
	}
	if strings.Contains(traces.String()+metrics.String(), "secret") {
		t.Fatal("exported secret error or export credentials")
	}
}

func TestOwnedHTTPPropagationAndSemanticDenial(t *testing.T) {
	m := New("control")
	exporter := tracetest.NewInMemoryExporter()
	m.tracerProvider = sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer m.Shutdown(context.Background())
	router := http.NewServeMux()
	router.HandleFunc("POST /decision/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !trace.SpanFromContext(r.Context()).SpanContext().IsValid() {
			t.Error("missing extracted span")
		}
		AuthorizationDecision(r.Context(), "fixture", false)
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(m.APIRequests("control", router))
	defer server.Close()
	ctx, parent := m.tracer().Start(WithMetrics(t.Context(), m), "fixture.parent")
	request, _ := http.NewRequestWithContext(ctx, "POST", server.URL+"/decision/secret-id?token=secret-query", strings.NewReader("secret-body"))
	request.Header.Set("Authorization", "Bearer secret-token")
	request.Header.Set("baggage", "secret-key=secret-value")
	response, err := OwnedHTTPClient(server.Client(), "control").Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	parent.End()
	spans := exporter.GetSpans()
	if len(spans) != 3 {
		t.Fatalf("spans=%d", len(spans))
	}
	var serverSpan, clientSpan *tracetest.SpanStub
	for i := range spans {
		switch spans[i].SpanKind {
		case trace.SpanKindServer:
			serverSpan = &spans[i]
		case trace.SpanKindClient:
			clientSpan = &spans[i]
		}
	}
	if serverSpan == nil || clientSpan == nil || serverSpan.Parent.SpanID() != clientSpan.SpanContext.SpanID() || serverSpan.SpanContext.TraceID() != parent.SpanContext().TraceID() {
		t.Fatal("trace context was not propagated across owned HTTP")
	}
	if serverSpan.Name != "control POST /decision/{id}" || serverSpan.Status.Description != "denied" {
		t.Fatalf("HTTP 200 denial was success: %+v", serverSpan)
	}
	for _, span := range spans {
		if strings.Contains(fmt.Sprint(span.Attributes, span.Status, span.Events), "secret") {
			t.Fatal("span leaked request content")
		}
	}
	text := metricsText(t, m)
	if !strings.Contains(text, `tnl_authorization_decisions_total{operation="fixture",result="denied"} 1`) || !strings.Contains(text, `outcome="denied"`) || strings.Contains(text, "secret") {
		t.Fatal("missing semantic denial or unsafe metric labels")
	}
}

func TestExporterFailureCannotBlockRecordingAndQueueDropsAreVisible(t *testing.T) {
	t.Setenv("OTEL_GO_X_OBSERVABILITY", "true")
	previousMeter, previousTrace, previousErrors := otel.GetMeterProvider(), otel.GetTracerProvider(), otel.GetErrorHandler()
	defer func() {
		otel.SetMeterProvider(previousMeter)
		otel.SetTracerProvider(previousTrace)
		otel.SetErrorHandler(previousErrors)
	}()
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(200 * time.Millisecond):
		}
		w.WriteHeader(503)
		_, _ = io.WriteString(w, "secret export rejection")
	}))
	defer receiver.Close()
	m, err := newOwner("publisher", Config{processOwner: true, SampleRatio: 1, QueueSize: 2, BatchSize: 1, BatchDelay: time.Hour, Traces: SignalConfig{Endpoint: receiver.URL + "/v1/traces", Timeout: 50 * time.Millisecond, TLS: receiver.Client().Transport.(*http.Transport).TLSClientConfig.Clone()}})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Shutdown(context.Background())
	ctx := WithMetrics(t.Context(), m)
	started := time.Now()
	for range 1000 {
		_, finish := PublisherOperation(ctx, "connect")
		finish(nil)
	}
	if time.Since(started) > time.Second {
		t.Fatal("export backpressure blocked recording")
	}
	readiness := httptest.NewRecorder()
	ProcessHandler(m.Handler(), func() bool { return true }).ServeHTTP(readiness, httptest.NewRequest("GET", "/ready", nil))
	if readiness.Code != http.StatusNoContent {
		t.Fatal("export failure changed process readiness")
	}
	flush, cancel := context.WithTimeout(t.Context(), time.Second)
	err = m.ForceFlush(flush)
	cancel()
	if err != nil && strings.Contains(err.Error(), "secret") {
		t.Fatal("export response leaked through flush")
	}
	text := metricsText(t, m)
	if !strings.Contains(text, `error_type="queue_full"`) || !strings.Contains(text, `tnl_observability_export_failures_total{signal="traces"} `) {
		t.Fatal("missing exporter/drop observations", text)
	}
	if strings.Contains(text, "secret") {
		t.Fatal("export credentials in metrics")
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started = time.Now()
	_ = m.Shutdown(shutdown)
	if time.Since(started) > time.Second {
		t.Fatal("shutdown exceeded caller bound")
	}
}

func TestPublisherIdentityCardinalityAndVisitorIDBoundary(t *testing.T) {
	m := New("publisher")
	exporter := tracetest.NewInMemoryExporter()
	m.tracerProvider = sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	defer m.Shutdown(context.Background())
	for i := range 2010 {
		ctx := WithIdentity(WithMetrics(t.Context(), m), Identity{TeamID: "team", PublisherID: "publisher", ServiceID: fmt.Sprint("service-", i)})
		ctx = WithVisitor(ctx, "visitor-high-churn")
		_, finish := PublisherOperation(ctx, "connect")
		finish(context.Canceled)
	}
	families, err := m.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == "tnl_publisher_operation_duration_seconds" && len(family.Metric) > 2000 {
			t.Fatal("metric cardinality is not bounded")
		}
	}
	text := metricsText(t, m)
	if strings.Contains(text, "visitor-high-churn") || !strings.Contains(text, "otel_metric_overflow") || !strings.Contains(text, `team_id="team"`) {
		t.Fatal("identity/overflow boundary failed")
	}
	if spans := exporter.GetSpans(); len(spans) == 0 || !containsAttribute(spans[0].Attributes, "visitor_connection_id", "visitor-high-churn") {
		t.Fatal("visitor correlation missing from span")
	}
}

func containsAttribute(attrs []attribute.KeyValue, key, value string) bool {
	for _, a := range attrs {
		if string(a.Key) == key && a.Value.AsString() == value {
			return true
		}
	}
	return false
}

func metricsText(t *testing.T, m *Metrics) string {
	t.Helper()
	w := httptest.NewRecorder()
	m.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	return w.Body.String()
}
