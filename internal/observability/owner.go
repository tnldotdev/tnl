package observability

import (
	"context"
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
	"go.opentelemetry.io/otel"
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
	config.processOwner = true
	// use the SDK's own bounded queue/drop instrumentation, rather than adding a
	// second queue. this SDK feature is enabled before constructing processors.
	if os.Getenv("OTEL_GO_X_OBSERVABILITY") == "" {
		_ = os.Setenv("OTEL_GO_X_OBSERVABILITY", "true")
	}
	m, err := newOwner(role, config)
	if err != nil {
		return ctx, nil, errors.New("initialize observability exporters")
	}
	return WithMetrics(ctx, m), m, nil
}

func WithMetrics(ctx context.Context, m *Metrics) context.Context {
	return context.WithValue(ctx, ownerKey{}, m)
}
func FromContext(ctx context.Context) *Metrics { m, _ := ctx.Value(ownerKey{}).(*Metrics); return m }

func newOwner(role string, config Config) (*Metrics, error) {
	exports := &exportState{}
	if config.processOwner {
		otel.SetErrorHandler(otel.ErrorHandlerFunc(func(error) { exports.sdkErrors.Add(1) }))
	}
	name := config.ServiceName
	if name == "" {
		name = "tnld"
		if role == "publisher" {
			name = "tnl"
		}
	}
	attrs := append([]attribute.KeyValue{}, config.Resource...)
	attrs = append(attrs, attribute.String("service.name", name), attribute.String("service.version", buildinfo.Version), attribute.String("tnl.role", role))
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
	opts := []sdkmetric.Option{sdkmetric.WithResource(res), sdkmetric.WithReader(scrape), sdkmetric.WithCardinalityLimit(2000), sdkmetric.WithView(func(i sdkmetric.Instrument) (sdkmetric.Stream, bool) {
		for prefix, owner := range map[string]string{"tnl_control_": "control", "tnl_database_": "control", "tnl_ingress_": "ingress", "tnl_relay_": "relay", "tnl_publisher_": "publisher"} {
			if strings.HasPrefix(i.Name, prefix) && role != owner && role != "standalone" {
				return sdkmetric.Stream{Aggregation: sdkmetric.AggregationDrop{}}, true
			}
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
		e, err := otlpmetrichttp.New(context.Background(), otlpmetrichttp.WithEndpointURL(s.Endpoint), otlpmetrichttp.WithHTTPClient(s.client()), otlpmetrichttp.WithHeaders(s.Headers), otlpmetrichttp.WithCompression(compression), otlpmetrichttp.WithRetry(otlpmetrichttp.RetryConfig{Enabled: false}), otlpmetrichttp.WithAggregationSelector(sdkmetric.DefaultAggregationSelector), otlpmetrichttp.WithMaxResponseSize(64<<10))
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
	if config.processOwner {
		otel.SetMeterProvider(mp)
	}
	m := &Metrics{meterProvider: mp, meter: mp.Meter(scope), registry: registry, runtimeRegistry: runtime}
	m.initInstruments(role)
	_, _ = m.meter.Int64ObservableCounter("tnl_observability_export_failures_total", metric.WithDescription("Failed export batches; export never gates readiness."), metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
		o.Observe(exports.metricsFailures.Load(), metric.WithAttributes(attribute.String("signal", "metrics")))
		o.Observe(exports.traceFailures.Load(), metric.WithAttributes(attribute.String("signal", "traces")))
		return nil
	}))
	_, _ = m.meter.Int64ObservableCounter("tnl_observability_export_lost_spans_total", metric.WithDescription("Spans lost in failed export batches; excludes SDK queue overflow."), metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error { o.Observe(exports.lostSpans.Load()); return nil }))
	_, _ = m.meter.Int64ObservableCounter("tnl_observability_sdk_errors_total", metric.WithDescription("SDK errors reported without endpoint, header, or response content."), metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error { o.Observe(exports.sdkErrors.Load()); return nil }))
	traceOptions := []sdktrace.TracerProviderOption{sdktrace.WithResource(res), sdktrace.WithSampler(sdktrace.NeverSample()), sdktrace.WithRawSpanLimits(sdktrace.SpanLimits{AttributeValueLengthLimit: 256, AttributeCountLimit: 32, EventCountLimit: 8, LinkCountLimit: 8, AttributePerEventCountLimit: 8, AttributePerLinkCountLimit: 8})}
	if config.Traces.Endpoint != "" && !config.Disabled {
		s := config.Traces
		compression := otlptracehttp.NoCompression
		if s.Gzip {
			compression = otlptracehttp.GzipCompression
		}
		e, err := otlptracehttp.New(context.Background(), otlptracehttp.WithEndpointURL(s.Endpoint), otlptracehttp.WithHTTPClient(s.client()), otlptracehttp.WithHeaders(s.Headers), otlptracehttp.WithCompression(compression), otlptracehttp.WithRetry(otlptracehttp.RetryConfig{Enabled: false}))
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
			sampler = sdktrace.ParentBased(sampler)
		}
		traceOptions = append(traceOptions, sdktrace.WithSampler(sampler), sdktrace.WithBatcher(exporter, sdktrace.WithMaxQueueSize(queue), sdktrace.WithMaxExportBatchSize(min(batch, queue)), sdktrace.WithBatchTimeout(delay), sdktrace.WithExportTimeout(s.Timeout)))
	}
	m.tracerProvider = sdktrace.NewTracerProvider(traceOptions...)
	if config.processOwner {
		otel.SetTracerProvider(m.tracerProvider)
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
	return errors.Join(m.tracerProvider.Shutdown(ctx), m.meterProvider.Shutdown(ctx))
}

func (m *Metrics) ForceFlush(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, ShutdownTimeout)
	defer cancel()
	return errors.Join(m.tracerProvider.ForceFlush(ctx), m.meterProvider.ForceFlush(ctx))
}

// exporters sanitize errors before the SDK can report them. neither endpoint
// URLs, response bodies nor authentication headers reach SDK diagnostics.
type metricExporter struct {
	sdkmetric.Exporter
	state *exportState
}

type exportState struct{ metricsFailures, traceFailures, lostSpans, sdkErrors atomic.Int64 }

func (e *metricExporter) Export(ctx context.Context, data *metricdata.ResourceMetrics) error {
	if err := e.Exporter.Export(ctx, data); err != nil {
		e.state.metricsFailures.Add(1)
		return errors.New("metrics export failed")
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
		return errors.New("trace export failed")
	}
	return nil
}
