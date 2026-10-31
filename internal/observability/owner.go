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
	"go.opentelemetry.io/otel/metric/noop"
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

func newOwner(role string, config Config) (_ *Metrics, err error) {
	parsedRole, ok := ParseRole(role)
	if !ok {
		return nil, errors.New("invalid observability process role")
	}
	if config.Disabled {
		// do not construct SDK providers: even explicit resource/limit options
		// are applied after their ambient defaults have been parsed and logged.
		m := &Metrics{meter: &contractMeter{Meter: noop.NewMeterProvider().Meter(scope), specs: make(map[string]InstrumentDefinition)}, registry: prometheus.NewRegistry(), runtimeRegistry: newRuntimeRegistry()}
		m.initInstruments(parsedRole)
		return m, nil
	}
	if err := validateSDKProviderEnvironment(os.Getenv); err != nil {
		return nil, err
	}
	// SDK constructors parse ambient settings before applying explicit options.
	// validate even overridden values before allowing those diagnostic paths.
	if config.Metrics.Endpoint != "" || config.Traces.Endpoint != "" || config.Logs.Endpoint != "" {
		if err := validateSDKEnvironment(os.Getenv); err != nil {
			return nil, err
		}
	}
	lifetime, cancelExports := context.WithCancel(context.Background())
	defer func() {
		if err != nil {
			cancelExports()
		}
	}()
	exports := &exportState{lifetime: lifetime}
	name := config.ServiceName
	if name == "" {
		name = "tnld"
		if parsedRole == RolePublisher || parsedRole == RoleClient {
			name = "tnl"
		}
		if parsedRole == RoleAccounts {
			name = "tnl-accounts"
		}
		if parsedRole == RoleCollector {
			name = "otel-collector"
		}
	}
	attrs := append([]attribute.KeyValue{}, config.Resource...)
	instance := ""
	for _, a := range attrs {
		if a.Key == attribute.Key(ServiceInstanceID.Key()) {
			instance = a.Value.AsString()
		}
	}
	if instance == "" {
		attrs = append(attrs, ServiceInstanceID.String(rand.Text()))
	}
	attrs = append(attrs, ServiceNamespace.String("tnl"), ServiceName.String(name), ServiceVersion.String(buildinfo.Version), RoleKey.Value(parsedRole))
	res := resource.NewSchemaless(attrs...)
	registry := prometheus.NewRegistry()
	// the supported bridge exports runtime/process collectors to OTLP. the OTel
	// Prometheus exporter deliberately skips bridged metrics, so scrape them from
	// the same runtime registry directly. application metrics never use the bridge.
	runtime := newRuntimeRegistry()
	scrape, err := otelprom.New(otelprom.WithRegisterer(registry), otelprom.WithoutScopeInfo(), otelprom.WithoutTargetInfo(), otelprom.WithTranslationStrategy(otlptranslator.UnderscoreEscapingWithoutSuffixes))
	if err != nil {
		return nil, err
	}
	catalog := &contractMeter{specs: make(map[string]InstrumentDefinition)}
	opts := []sdkmetric.Option{sdkmetric.WithResource(res), sdkmetric.WithReader(scrape), sdkmetric.WithCardinalityLimit(2000), sdkmetric.WithView(func(i sdkmetric.Instrument) (sdkmetric.Stream, bool) {
		for prefix, owner := range map[string]Role{"tnl_control_": RoleControl, "tnl_database_": RoleControl, "tnl_ingress_": RoleIngress, "tnl_relay_": RoleRelay, "tnl_publisher_": RolePublisher} {
			if strings.HasPrefix(i.Name, prefix) && parsedRole != owner && parsedRole != RoleStandalone {
				return sdkmetric.Stream{Aggregation: sdkmetric.AggregationDrop{}}, true
			}
		}
		if spec, ok := catalog.definition(i.Name); ok {
			return sdkmetric.Stream{Name: i.Name, Description: i.Description, Unit: i.Unit, ExemplarReservoirProviderSelector: correlationOnlyReservoir, AttributeFilter: func(kv attribute.KeyValue) bool {
				return Key(kv.Key) != MetricOverflow.key() && slicesContainsKey(spec.Dimensions, Key(kv.Key)) && validMetricValue(kv)
			}}, true
		}
		return sdkmetric.Stream{}, false
	})}
	var metricExport *metricExporter
	if config.Metrics.Endpoint != "" {
		s := config.Metrics
		compression := otlpmetrichttp.NoCompression
		if s.Gzip {
			compression = otlpmetrichttp.GzipCompression
		}
		e, err := otlpmetrichttp.New(context.Background(), otlpmetrichttp.WithEndpointURL(s.Endpoint), otlpmetrichttp.WithHTTPClient(s.client()), otlpmetrichttp.WithHeaders(s.Headers), otlpmetrichttp.WithCompression(compression), otlpmetrichttp.WithRetry(otlpmetrichttp.RetryConfig{Enabled: true, InitialInterval: 100 * time.Millisecond, MaxInterval: time.Second, MaxElapsedTime: s.Timeout}), otlpmetrichttp.WithTemporalitySelector(sdkmetric.CumulativeTemporalitySelector), otlpmetrichttp.WithAggregationSelector(sdkmetric.DefaultAggregationSelector), otlpmetrichttp.WithMaxResponseSize(64<<10))
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
	m := &Metrics{meterProvider: mp, meter: catalog, registry: registry, runtimeRegistry: runtime, resource: res, cancelExports: cancelExports}
	m.initInstruments(parsedRole)
	describe(m.meter, "tnl_observability_export_failures_total", "Failed export batches after bounded retries; never gates readiness.", KindCounter, nil, signalKey)
	_, _ = m.meter.Int64ObservableCounter("tnl_observability_export_failures_total", metric.WithDescription("Failed export batches; export never gates readiness."), metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
		o.Observe(exports.metricsFailures.Load(), metric.WithAttributes(attribute.String("tnl.signal", "metrics")))
		o.Observe(exports.traceFailures.Load(), metric.WithAttributes(attribute.String("tnl.signal", "traces")))
		o.Observe(exports.logFailures.Load(), metric.WithAttributes(attribute.String("tnl.signal", "logs")))
		return nil
	}))
	describe(m.meter, "tnl_observability_export_lost_spans_total", "Spans lost in failed export batches; excludes queue overflow.", KindCounter, nil)
	_, _ = m.meter.Int64ObservableCounter("tnl_observability_export_lost_spans_total", metric.WithDescription("Spans lost in failed export batches; excludes queue overflow."), metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error { o.Observe(exports.lostSpans.Load()); return nil }))
	describe(m.meter, "tnl_observability_queue_dropped_spans_total", "Sampled spans dropped by the bounded nonblocking export queue.", KindCounter, nil)
	_, _ = m.meter.Int64ObservableCounter("tnl_observability_queue_dropped_spans_total", metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
		o.Observe(exports.droppedSpans.Load())
		return nil
	}))
	// raw zero drops all link attributes rather than restoring the SDK default.
	// links carry bounded causal IDs, never scheduling or tenant payloads.
	traceOptions := []sdktrace.TracerProviderOption{sdktrace.WithoutPanicRecording(), sdktrace.WithResource(res), sdktrace.WithIDGenerator(xrayIDGenerator{}), sdktrace.WithSampler(sdktrace.NeverSample()), sdktrace.WithRawSpanLimits(sdktrace.SpanLimits{AttributeValueLengthLimit: 256, AttributeCountLimit: 32, EventCountLimit: 8, LinkCountLimit: 8, AttributePerEventCountLimit: 8, AttributePerLinkCountLimit: 0})}
	if config.Traces.Endpoint != "" {
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
		m.spanQueue = newSpanQueue(exporter, exports, queue, min(batch, queue), delay, s.Timeout)
		traceOptions = append(traceOptions, sdktrace.WithSampler(sampler), sdktrace.WithSpanProcessor(m.spanQueue))
	}
	m.tracerProvider = sdktrace.NewTracerProvider(traceOptions...)
	if err := m.initLogs(config, res, exports); err != nil {
		_ = m.Shutdown(context.Background())
		return nil, err
	}
	return m, nil
}

func newRuntimeRegistry() *prometheus.Registry {
	runtime := prometheus.NewRegistry()
	runtime.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return runtime
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
	if m.cancelExports != nil {
		stop := context.AfterFunc(ctx, m.cancelExports)
		defer stop()
		defer m.cancelExports()
		if ctx.Err() != nil {
			m.cancelExports()
		}
	}
	return providerWork(ctx, func(ctx context.Context) error {
		var err error
		// the SDK can skip processors on an already canceled context. the owner
		// must stop its workers even in that case.
		if m.spanQueue != nil {
			err = m.spanQueue.Shutdown(ctx)
		}
		if m.tracerProvider != nil {
			err = errors.Join(err, m.tracerProvider.Shutdown(ctx))
		}
		return err
	}, func(ctx context.Context) error {
		var err error
		if m.logProcessor != nil {
			err = m.logProcessor.Shutdown(ctx)
		}
		if m.loggerProvider != nil {
			err = errors.Join(err, m.loggerProvider.Shutdown(ctx))
		}
		return err
	}, func(ctx context.Context) error {
		if m.meterProvider != nil {
			return m.meterProvider.Shutdown(ctx)
		}
		return nil
	})
}

func (m *Metrics) ForceFlush(ctx context.Context) error {
	if m == nil {
		return nil
	}
	return providerWork(ctx, func(ctx context.Context) error {
		if m.tracerProvider != nil {
			return m.tracerProvider.ForceFlush(ctx)
		}
		return nil
	}, func(ctx context.Context) error {
		if m.loggerProvider != nil {
			return m.loggerProvider.ForceFlush(ctx)
		}
		return nil
	}, func(ctx context.Context) error {
		if m.meterProvider != nil {
			return m.meterProvider.ForceFlush(ctx)
		}
		return nil
	})
}

// each provider starts independently; one slow signal cannot consume another's
// entire budget. errors retain all causes but format only authored text.
func providerWork(ctx context.Context, work ...func(context.Context) error) error {
	caller := ctx
	ctx, cancel := context.WithTimeout(ctx, ShutdownTimeout)
	defer cancel()
	results := make(chan error, len(work))
	for _, fn := range work {
		go func() { results <- fn(ctx) }()
	}
	var err error
	for range work {
		err = errors.Join(err, <-results)
	}
	// cleanup can finish while caller cancellation is still reaching this child.
	// retain the caller's cause as well as the helper's own timeout.
	err = errors.Join(err, context.Cause(ctx), context.Cause(caller))
	if err != nil {
		return safeExportError("observability provider operation failed", err)
	}
	return nil
}

// exporters sanitize errors before the SDK can report them. neither endpoint
// URLs, response bodies nor authentication headers reach SDK diagnostics.
type metricExporter struct {
	sdkmetric.Exporter
	state *exportState
}

type exportState struct {
	metricsFailures, traceFailures, logFailures, lostSpans, droppedSpans atomic.Int64
	lifetime                                                             context.Context
}

func (s *exportState) exportContext(ctx context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)
	if s.lifetime == nil {
		return ctx, cancel
	}
	stop := context.AfterFunc(s.lifetime, cancel)
	if s.lifetime.Err() != nil {
		cancel()
	}
	return ctx, func() { stop(); cancel() }
}

func (e *metricExporter) Export(ctx context.Context, data *metricdata.ResourceMetrics) error {
	ctx, cancel := e.state.exportContext(ctx)
	defer cancel()
	if ctx.Err() != nil {
		return ctx.Err()
	}
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
