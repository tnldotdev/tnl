package observability

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/otlptranslator"
	"github.com/tnldotdev/tnl/internal/buildinfo"
	bridge "go.opentelemetry.io/contrib/bridges/prometheus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

const scope = "github.com/tnldotdev/tnl/internal/observability"
const ShutdownTimeout = 5 * time.Second

type ownerKey struct{}

// StartProcess is called once by the native process entry point. child workers
// inherit its context; they do not create providers or read export settings.
func StartProcess(ctx context.Context, role string) (context.Context, *Metrics, error) {
	config, err := ConfigFromEnv(os.Getenv)
	if err != nil {
		return ctx, nil, err
	}
	m, err := newOwner(role, config)
	if err != nil {
		return ctx, nil, safeExportError("initialize observability exporters", err)
	}
	return WithMetrics(ctx, m), m, nil
}

func WithMetrics(ctx context.Context, m *Metrics) context.Context {
	return context.WithValue(ctx, ownerKey{}, m)
}
func FromContext(ctx context.Context) *Metrics { m, _ := ctx.Value(ownerKey{}).(*Metrics); return m }

func newOwner(role string, config Config) (*Metrics, error) {
	exports := &exportState{}
	name := config.ServiceName
	if name == "" {
		name = "tnld"
		if role == "publisher" || role == "client" {
			name = "tnl"
		}
		if role == "accounts" {
			name = "tnl-accounts"
		}
		if role == "collector" {
			name = "otel-collector"
		}
	}
	attrs := append([]attribute.KeyValue{}, config.Resource...)
	instance := ""
	for _, a := range attrs {
		if a.Key == attribute.Key(ServiceInstanceID) {
			instance = a.Value.AsString()
		}
	}
	if instance == "" {
		attrs = append(attrs, ServiceInstanceID.String(rand.Text()))
	}
	attrs = append(attrs, ServiceNamespace.String("tnl"), ServiceName.String(name), ServiceVersion.String(buildinfo.Version), RoleKey.String(role))
	res := resource.NewSchemaless(attrs...)
	registry := prometheus.NewRegistry()
	// the supported bridge exports runtime/process collectors to OTLP. the OTel
	// Prometheus exporter deliberately skips bridged metrics, so scrape them from
	// the same runtime registry directly. application metrics never use the bridge.
	runtime := prometheus.NewRegistry()
	runtime.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	scrape, err := otelprom.New(otelprom.WithRegisterer(registry), otelprom.WithoutScopeInfo(), otelprom.WithoutTargetInfo(), otelprom.WithTranslationStrategy(otlptranslator.UnderscoreEscapingWithoutSuffixes))
	if err != nil {
		return nil, err
	}
	catalog := &contractMeter{specs: make(map[string]InstrumentDefinition)}
	opts := []sdkmetric.Option{sdkmetric.WithResource(res), sdkmetric.WithReader(scrape), sdkmetric.WithCardinalityLimit(2000), sdkmetric.WithView(func(i sdkmetric.Instrument) (sdkmetric.Stream, bool) {
		if config.Disabled {
			return sdkmetric.Stream{Aggregation: sdkmetric.AggregationDrop{}}, true
		}
		for prefix, owner := range map[string]string{"tnl_control_": "control", "tnl_database_": "control", "tnl_ingress_": "ingress", "tnl_relay_": "relay", "tnl_publisher_": "publisher"} {
			if strings.HasPrefix(i.Name, prefix) && role != owner && role != "standalone" {
				return sdkmetric.Stream{Aggregation: sdkmetric.AggregationDrop{}}, true
			}
		}
		if spec, ok := catalog.definition(i.Name); ok {
			return sdkmetric.Stream{Name: i.Name, Description: i.Description, Unit: i.Unit, AttributeFilter: func(kv attribute.KeyValue) bool {
				return slicesContainsKey(spec.Dimensions, Key(kv.Key)) && validMetricValue(kv)
			}}, true
		}
		return sdkmetric.Stream{}, false
	})}
	var metricExport *metricExporter
	if config.Metrics.Endpoint != "" && !config.Disabled {
		s := config.Metrics
		compression := otlpmetrichttp.NoCompression
		if s.Gzip {
			compression = otlpmetrichttp.GzipCompression
		}
		e, err := otlpmetrichttp.New(context.Background(), otlpmetrichttp.WithEndpointURL(s.Endpoint), otlpmetrichttp.WithHTTPClient(s.client()), otlpmetrichttp.WithHeaders(s.Headers), otlpmetrichttp.WithCompression(compression), otlpmetrichttp.WithRetry(otlpmetrichttp.RetryConfig{Enabled: true, InitialInterval: 100 * time.Millisecond, MaxInterval: time.Second, MaxElapsedTime: s.Timeout}), otlpmetrichttp.WithAggregationSelector(sdkmetric.DefaultAggregationSelector), otlpmetrichttp.WithMaxResponseSize(64<<10))
		if err != nil {
			return nil, err
		}
		metricExport = &metricExporter{Exporter: e, state: exports}
		interval := config.Interval
		if interval <= 0 {
			interval = 60 * time.Second
		}
		reader := sdkmetric.NewPeriodicReader(metricExport, sdkmetric.WithInterval(interval), sdkmetric.WithTimeout(s.Timeout), sdkmetric.WithProducer(bridge.NewMetricProducer(bridge.WithGatherer(runtime))))
		opts = append(opts, sdkmetric.WithReader(reader))
	}
	mp := sdkmetric.NewMeterProvider(opts...)
	catalog.Meter = mp.Meter(scope)
	m := &Metrics{meterProvider: mp, meter: catalog, registry: registry, runtimeRegistry: runtime, resource: res}
	m.initInstruments(role)
	describe(m.meter, "tnl_observability_export_failures_total", "Failed export batches after bounded retries; never gates readiness.", "counter", nil, "signal")
	_, _ = m.meter.Int64ObservableCounter("tnl_observability_export_failures_total", metric.WithDescription("Failed export batches; export never gates readiness."), metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
		o.Observe(exports.metricsFailures.Load(), metric.WithAttributes(attribute.String("tnl.signal", "metrics")))
		o.Observe(exports.traceFailures.Load(), metric.WithAttributes(attribute.String("tnl.signal", "traces")))
		o.Observe(exports.logFailures.Load(), metric.WithAttributes(attribute.String("tnl.signal", "logs")))
		return nil
	}))
	describe(m.meter, "tnl_observability_export_lost_spans_total", "Spans lost in failed export batches; excludes queue overflow.", "counter", nil)
	_, _ = m.meter.Int64ObservableCounter("tnl_observability_export_lost_spans_total", metric.WithDescription("Spans lost in failed export batches; excludes queue overflow."), metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error { o.Observe(exports.lostSpans.Load()); return nil }))
	describe(m.meter, "tnl_observability_queue_dropped_spans_total", "Sampled spans dropped by the bounded nonblocking export queue.", "counter", nil)
	_, _ = m.meter.Int64ObservableCounter("tnl_observability_queue_dropped_spans_total", metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
		o.Observe(exports.droppedSpans.Load())
		return nil
	}))
	traceOptions := []sdktrace.TracerProviderOption{sdktrace.WithResource(res), sdktrace.WithIDGenerator(xrayIDGenerator{}), sdktrace.WithSampler(sdktrace.NeverSample()), sdktrace.WithRawSpanLimits(sdktrace.SpanLimits{AttributeValueLengthLimit: 256, AttributeCountLimit: 32, EventCountLimit: 8, LinkCountLimit: 8, AttributePerEventCountLimit: 8, AttributePerLinkCountLimit: 8})}
	if config.Traces.Endpoint != "" && !config.Disabled {
		s := config.Traces
		compression := otlptracehttp.NoCompression
		if s.Gzip {
			compression = otlptracehttp.GzipCompression
		}
		e, err := otlptracehttp.New(context.Background(), otlptracehttp.WithEndpointURL(s.Endpoint), otlptracehttp.WithHTTPClient(s.client()), otlptracehttp.WithHeaders(s.Headers), otlptracehttp.WithCompression(compression), otlptracehttp.WithRetry(otlptracehttp.RetryConfig{Enabled: true, InitialInterval: 100 * time.Millisecond, MaxInterval: time.Second, MaxElapsedTime: s.Timeout}))
		if err != nil {
			_ = mp.Shutdown(context.Background())
			return nil, err
		}
		exporter := &spanExporter{SpanExporter: e, state: exports}
		queue, batch, delay := config.QueueSize, config.BatchSize, config.BatchDelay
		if queue <= 0 {
			queue = 2048
		}
		if batch <= 0 {
			batch = 512
		}
		if delay <= 0 {
			delay = 5 * time.Second
		}
		var sampler sdktrace.Sampler = sdktrace.TraceIDRatioBased(config.SampleRatio)
		if config.Sampler == "" || strings.HasPrefix(config.Sampler, "parentbased_") {
			// remote trace flags are untrusted. every externally supplied parent
			// uses this process's configured policy; local children retain their
			// parent's decision so one visitor's local spans stay coherent.
			sampler = sdktrace.ParentBased(sampler, sdktrace.WithRemoteParentSampled(sampler), sdktrace.WithRemoteParentNotSampled(sampler))
		}
		traceOptions = append(traceOptions, sdktrace.WithSampler(sampler), sdktrace.WithSpanProcessor(newSpanQueue(exporter, exports, queue, min(batch, queue), delay, s.Timeout)))
	}
	m.tracerProvider = sdktrace.NewTracerProvider(traceOptions...)
	if err := m.initLogs(config, res, exports); err != nil {
		_ = m.Shutdown(context.Background())
		return nil, err
	}
	return m, nil
}

// Shutdown has one shared deadline, independent of the canceled traffic context.
// callers invoke it after draining workers; export errors never become traffic
// errors. the providers themselves make repeated shutdown harmless.
func (m *Metrics) Shutdown(ctx context.Context) error {
	if m == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, ShutdownTimeout)
	defer cancel()
	var logs error
	if m.loggerProvider != nil {
		logs = m.loggerProvider.Shutdown(ctx)
	}
	return errors.Join(m.tracerProvider.Shutdown(ctx), logs, m.meterProvider.Shutdown(ctx))
}

func (m *Metrics) ForceFlush(ctx context.Context) error {
	if m == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, ShutdownTimeout)
	defer cancel()
	var logs error
	if m.loggerProvider != nil {
		logs = m.loggerProvider.ForceFlush(ctx)
	}
	return errors.Join(m.tracerProvider.ForceFlush(ctx), logs, m.meterProvider.ForceFlush(ctx))
}

// exporters sanitize errors before the SDK can report them. neither endpoint
// URLs, response bodies nor authentication headers reach SDK diagnostics.
type metricExporter struct {
	sdkmetric.Exporter
	state *exportState
}

type exportState struct{ metricsFailures, traceFailures, logFailures, lostSpans, droppedSpans atomic.Int64 }

func (e *metricExporter) Export(ctx context.Context, data *metricdata.ResourceMetrics) error {
	if err := e.Exporter.Export(ctx, data); err != nil {
		e.state.metricsFailures.Add(1)
		return safeExportError("metrics export failed", err)
	}
	return nil
}

type spanExporter struct {
	sdktrace.SpanExporter
	state *exportState
}

func (e *spanExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	if err := e.SpanExporter.ExportSpans(ctx, spans); err != nil {
		e.state.traceFailures.Add(1)
		e.state.lostSpans.Add(int64(len(spans)))
		return safeExportError("trace export failed", err)
	}
	return nil
}

// exportError retains cause identity while formatting only authored text.
type exportError struct {
	message string
	cause   error
}

func (e *exportError) Error() string                    { return e.message }
func (e *exportError) GoString() string                 { return e.message }
func (e *exportError) Unwrap() error                    { return e.cause }
func safeExportError(message string, cause error) error { return &exportError{message, cause} }
func slicesContainsKey(keys []Key, key Key) bool {
	for _, k := range keys {
		if k == key {
			return true
		}
	}
	return false
}
