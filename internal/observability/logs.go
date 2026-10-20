package observability

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/trace"
)

func (m *Metrics) initLogs(config Config, res *resource.Resource, state *exportState) error {
	if config.Disabled || config.Logs.Endpoint == "" {
		return nil
	}
	s := config.Logs
	compression := otlploghttp.NoCompression
	if s.Gzip {
		compression = otlploghttp.GzipCompression
	}
	e, err := otlploghttp.New(context.Background(), otlploghttp.WithEndpointURL(s.Endpoint), otlploghttp.WithHTTPClient(s.client()), otlploghttp.WithHeaders(s.Headers), otlploghttp.WithCompression(compression), otlploghttp.WithRetry(otlploghttp.RetryConfig{Enabled: true, InitialInterval: 100 * time.Millisecond, MaxInterval: time.Second, MaxElapsedTime: s.Timeout}))
	if err != nil {
		return safeExportError("initialize log export", err)
	}
	queue, batch, delay := config.LogQueueSize, config.LogBatchSize, config.LogBatchDelay
	if queue <= 0 {
		queue = 2048
	}
	if batch <= 0 {
		batch = 512
	}
	if delay <= 0 {
		delay = time.Second
	}
	m.logProcessor = sdklog.NewBatchProcessor(&logExporter{e, state}, sdklog.WithMaxQueueSize(queue), sdklog.WithExportMaxBatchSize(min(batch, queue)), sdklog.WithExportInterval(delay), sdklog.WithExportTimeout(s.Timeout))
	m.loggerProvider = sdklog.NewLoggerProvider(sdklog.WithResource(res), sdklog.WithAttributeCountLimit(32), sdklog.WithAttributeValueLengthLimit(256), sdklog.WithProcessor(m.logProcessor))
	return nil
}

type logExporter struct {
	sdklog.Exporter
	state *exportState
}

func (e *logExporter) Export(ctx context.Context, records []sdklog.Record) error {
	ctx, cancel := e.state.exportContext(ctx)
	defer cancel()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := e.Exporter.Export(ctx, records); err != nil {
		e.state.logFailures.Add(1)
		return safeExportError("log export failed", err)
	}
	return nil
}

// Correlation returns only OTel trace identifiers for existing one-line logs.
// it does not format request input or copy arbitrary context values.
func Correlation(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return ""
	}
	return fmt.Sprintf(" trace_id=%s span_id=%s", sc.TraceID(), sc.SpanID())
}

// OperationalFailure exports authored failure copy with scoped identity and trace
// correlation. it never accepts a free-form log body or exports cause.Error().
func OperationalFailure(ctx context.Context, operation failure.Operation, reason failure.Reason, requestID string, cause error) {
	m := FromContext(ctx)
	if m == nil || m.loggerProvider == nil || cause == nil {
		return
	}
	if specific, ok := failure.ReasonOf(cause); ok {
		reason = specific
	}
	def, ok := failure.DefinitionFor(reason)
	if !ok {
		reason = failure.Unexpected
		def, _ = failure.DefinitionFor(reason)
	}
	var record log.Record
	record.SetTimestamp(time.Now())
	record.SetObservedTimestamp(time.Now())
	record.SetSeverity(log.SeverityError)
	record.SetSeverityText("error")
	record.SetBody(attribute.StringValue(def.Message))
	record.AddAttributes(Operation.String(operationID(operation)), Event.String("operational_failure"), OutcomeKey.String(string(ErrorOutcome(cause))), ErrorType.String(string(reason)))
	if requestID != "" && len(requestID) <= 128 {
		record.AddAttributes(RequestID.String(requestID))
	}
	for _, a := range identityAttributes(ctx) {
		record.AddAttributes(a)
	}
	m.loggerProvider.Logger(scope).Emit(ctx, record)
}

// operation is authored by the caller, never taken from a cause or request. keep
// its words while producing a stable identifier accepted by the shared contract.
func operationID(operation failure.Operation) string {
	value := strings.ToLower(strings.Join(strings.Fields(string(operation)), "_"))
	if len(value) == 0 || len(value) > 128 {
		return "operational_failure"
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return "operational_failure"
		}
	}
	return value
}
