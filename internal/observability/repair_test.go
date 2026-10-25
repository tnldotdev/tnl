package observability

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

func TestNativeOTLPPanicIsErrorWithoutExceptionOrSecret(t *testing.T) {
	for _, wrote := range []bool{false, true} {
		t.Run(fmt.Sprint(wrote), func(t *testing.T) {
			f := newLinkTraceFixture(t, 1)
			mux := http.NewServeMux()
			mux.HandleFunc("GET /panic", func(w http.ResponseWriter, r *http.Request) {
				_, span := f.owner.tracer().Start(r.Context(), "direct.panic")
				defer span.End() // exercise the SDK's automatic panic path too
				if wrote {
					w.WriteHeader(200)
				}
				panic("secret panic credential")
			})
			func() {
				defer func() {
					if got := recover(); got != "secret panic credential" {
						t.Fatalf("panic was replaced or swallowed: %v", got)
					}
				}()
				f.owner.APIRequests("control", mux).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/panic", nil))
			}()
			spans := f.exported(t)
			span := spans["control GET /panic"]
			if len(spans) != 2 || span == nil || span.Status.Code != tracepb.Status_STATUS_CODE_ERROR {
				t.Fatal("panic handler was recorded as success", spans)
			}
			for _, a := range span.Attributes {
				if a.Key == string(HTTPStatus.Key()) && !wrote {
					t.Fatal("invented a response status for interrupted handler")
				}
			}
			if got := dataMetric(t, f.owner, "tnl_api_request_duration_seconds", map[string]string{"tnl_outcome": "error"}); got != 1 {
				t.Fatal("panic missing from request errors", got)
			}
			if got := dataMetric(t, f.owner, "tnl_api_requests_in_flight", nil); got != 0 {
				t.Fatal("panic leaked in-flight request", got)
			}
		})
	}
}

func TestNativeOTLPCompletedOperationsKeepDistinctMachineNames(t *testing.T) {
	f := newLinkTraceFixture(t, 1)
	f.owner.completedSpan("database.commit", "success", time.Millisecond)
	_, finish := f.owner.completedOperation(WithMetrics(t.Context(), f.owner), "database.rollback", time.Millisecond)
	finish(nil)
	for name, span := range f.exported(t) {
		found := false
		for _, a := range span.Attributes {
			found = found || a.Key == string(Operation.Key()) && a.Value.GetStringValue() == name
		}
		if !found {
			t.Fatal("completed operation loses its exported identity", name)
		}
	}
}

func TestNativeAPIInformationalHeadersDoNotReplaceFinalStatus(t *testing.T) {
	f := newLinkTraceFixture(t, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /hints", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(103) })
	server := httptest.NewServer(f.owner.APIRequests("control", mux))
	defer server.Close()
	response, err := server.Client().Get(server.URL + "/hints")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("net/http did not send the final implicit 200")
	}
	span := f.exported(t)["control GET /hints"]
	if span == nil {
		t.Fatal("API span missing")
	}
	found := false
	for _, a := range span.Attributes {
		if a.Key == string(HTTPStatus.Key()) {
			found = a.Value.GetIntValue() == 200
		}
	}
	if !found {
		t.Fatal("API measurement replaced final status with informational headers")
	}
}

var constructorSetting = flag.String("tnl-observability-constructor-setting", "", "isolated observability constructor regression child")

func TestNativeExporterConstructorsRejectAmbientSecretsBeforeSDKLogging(t *testing.T) {
	if *constructorSetting != "" {
		_, err := ConfigFromEnv(os.Getenv)
		assertSetting := func(err error) {
			t.Helper()
			typed, ok := failure.Of(err)
			if !ok || string(typed.Setting()) != *constructorSetting || strings.Contains(fmt.Sprintf("%+v", err), "secret") {
				t.Fatalf("missing safe setting classification: %v", err)
			}
		}
		assertSetting(err)
		// explicit settings cannot make the ambient SDK parse safe on their own.
		signal := SignalConfig{Endpoint: "https://127.0.0.1:1/v1/traces", Timeout: time.Millisecond}
		for _, config := range []Config{{Traces: signal}, {Metrics: signal}, {Logs: signal}} {
			m, err := newOwner("publisher", config)
			if m != nil {
				_ = m.Shutdown(t.Context())
			}
			assertSetting(err)
		}
		return
	}
	for key, value := range map[string]string{
		"OTEL_EXPORTER_OTLP_HEADERS":                               "Authorization=secret%zz",
		"OTEL_EXPORTER_OTLP_ENDPOINT":                              "https://secret%zz.invalid",
		"OTEL_EXPORTER_OTLP_TIMEOUT":                               "secret-timeout",
		"OTEL_EXPORTER_OTLP_CERTIFICATE":                           "/missing/secret-ca.pem",
		"OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE":                    "/missing/secret-client.pem",
		"OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE":        "secret-temporality",
		"OTEL_EXPORTER_OTLP_METRICS_DEFAULT_HISTOGRAM_AGGREGATION": "secret-aggregation",
		"OTEL_TRACES_SAMPLER":                                      "secret-sampler",
		"OTEL_METRIC_EXPORT_INTERVAL":                              "secret-interval",
		"OTEL_GO_X_CARDINALITY_LIMIT":                              "secret-cardinality",
	} {
		t.Run(key, func(t *testing.T) {
			command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestNativeExporterConstructorsRejectAmbientSecretsBeforeSDKLogging$", "-tnl-observability-constructor-setting="+key)
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "OTEL_") {
					command.Env = append(command.Env, entry)
				}
			}
			for _, signal := range []string{"METRICS", "TRACES", "LOGS"} {
				command.Env = append(command.Env, "OTEL_EXPORTER_OTLP_"+signal+"_ENDPOINT=https://collector.invalid/v1/"+strings.ToLower(signal), "OTEL_EXPORTER_OTLP_"+signal+"_HEADERS=x-key=valid", "OTEL_EXPORTER_OTLP_"+signal+"_TIMEOUT=100")
			}
			command.Env = append(command.Env, key+"="+value)
			var stderr bytes.Buffer
			command.Stderr = &stderr
			stdout, err := command.Output()
			if err != nil || stderr.Len() != 0 {
				t.Fatalf("constructor child: %v stdout=%s stderr=%s", err, stdout, &stderr)
			}
		})
	}
}

func TestMetricTemporalityRejectsDeltaAndLowMemory(t *testing.T) {
	const key = "OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE"
	for _, value := range []string{"delta", "lowmemory", "invalid"} {
		_, err := ConfigFromEnv(func(k string) string {
			if k == key {
				return value
			}
			return ""
		})
		if typed, ok := failure.Of(err); !ok || string(typed.Setting()) != key {
			t.Fatal("unsupported temporality accepted", value, err)
		}
	}
}

type shutdownLogExporter struct {
	started chan struct{}
	done    chan struct{}
	once    sync.Once
}

func TestProviderWorkRetainsDeadlineWhenProvidersReturnNil(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	started := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		finished <- providerWork(ctx, func(ctx context.Context) error {
			close(started)
			<-ctx.Done()
			return nil
		})
	}()
	<-started
	cancel()
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatal("provider success hid owner cancellation", err)
	}
}

func (e *shutdownLogExporter) Export(ctx context.Context, _ []sdklog.Record) error {
	e.once.Do(func() { close(e.started) })
	<-ctx.Done()
	return ctx.Err()
}
func (*shutdownLogExporter) ForceFlush(context.Context) error { return nil }
func (e *shutdownLogExporter) Shutdown(context.Context) error { close(e.done); return nil }

func TestOwnerShutdownStartsTraceDrainWhileLogsAreSlow(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprint(expired), func(t *testing.T) {
			m := New("publisher")
			logs := &shutdownLogExporter{started: make(chan struct{}), done: make(chan struct{})}
			lifetime, cancelExports := context.WithCancel(context.Background())
			m.cancelExports = cancelExports
			m.logProcessor = sdklog.NewBatchProcessor(&logExporter{logs, &exportState{lifetime: lifetime}}, sdklog.WithExportMaxBatchSize(1), sdklog.WithExportInterval(time.Hour), sdklog.WithExportTimeout(10*time.Second))
			m.loggerProvider = sdklog.NewLoggerProvider(sdklog.WithProcessor(m.logProcessor))
			OperationalFailure(WithMetrics(t.Context(), m), "renew publisher", failure.Unexpected, "", errors.New("secret"))
			<-logs.started
			var exports atomic.Int64
			e := &countingTraceExporter{exports: &exports}
			m.spanQueue = newSpanQueue(e, &exportState{}, 4, 4, time.Hour, time.Second)
			m.tracerProvider = sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(m.spanQueue))
			_, span := m.tracer().Start(t.Context(), "queued")
			span.End()
			bound, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
			defer cancel()
			if expired {
				cancel()
			}
			started := time.Now()
			err := m.Shutdown(bound)
			if !errors.Is(err, bound.Err()) || time.Since(started) > time.Second {
				t.Fatal("shutdown lost cause or exceeded shared bound", err)
			}
			select {
			case <-m.spanQueue.done:
			case <-time.After(time.Second):
				t.Fatal("trace worker survived shutdown")
			}
			select {
			case <-logs.done:
			case <-time.After(time.Second):
				t.Fatal("log worker survived shutdown")
			}
			before := exports.Load()
			if !expired && before != 1 {
				t.Fatal("slow logs prevented trace drain", before)
			}
			if expired && before != 0 {
				t.Fatal("export started after expired bound", before)
			}
			_, after := m.tracer().Start(t.Context(), "after shutdown")
			after.End()
			if exports.Load() != before {
				t.Fatal("export continued after shutdown")
			}
		})
	}
}

type countingTraceExporter struct{ exports *atomic.Int64 }

func (e *countingTraceExporter) ExportSpans(ctx context.Context, _ []sdktrace.ReadOnlySpan) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	e.exports.Add(1)
	return nil
}
func (*countingTraceExporter) Shutdown(context.Context) error { return nil }

// the real OTLP export test also checks these definitions against actual bridge
// data; a summary must never be mistaken for a bucket histogram by the consumer.
func assertRuntimeContract(t *testing.T, metrics []*metricspb.Metric) {
	t.Helper()
	seen := map[string]bool{}
	for _, spec := range RuntimeInstrumentDefinitions() {
		for _, m := range metrics {
			if m.Name != spec.Name {
				continue
			}
			seen[m.Name] = true
			if spec.Kind == KindGauge && m.GetGauge() == nil || spec.Kind == KindCounter && (m.GetSum() == nil || !m.GetSum().IsMonotonic || m.GetSum().AggregationTemporality != metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE) || spec.Kind == KindSummary && m.GetSummary() == nil {
				t.Fatal("runtime bridge changed the shared semantic type", spec.Name)
			}
		}
	}
	for _, required := range []string{"go_goroutines", "go_gc_duration_seconds", "go_memstats_heap_alloc_bytes", "process_start_time_seconds"} {
		if !seen[required] {
			t.Fatal("compiled bridge name missing", required)
		}
	}
}

func TestMetricOverflowCannotBeForgedByInstrumentCaller(t *testing.T) {
	m := New("publisher")
	defer m.Shutdown(t.Context())
	m.publisherOperations.Record(t.Context(), .01, metric.WithAttributes(MetricOverflow.Bool(true), attribute.String("unapproved", "secret")))
	if strings.Contains(metricsText(t, m), "otel_metric_overflow") {
		t.Fatal("caller supplied an SDK overflow marker")
	}
}
