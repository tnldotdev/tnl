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
	record.AddAttributes(Operation.Value(operationID(operation)), Event.Value(EventOperationalFailure), OutcomeKey.Value(ErrorOutcome(cause)), ErrorType.String(string(reason)))
	if requestID != "" && len(requestID) <= 128 {
		record.AddAttributes(RequestID.String(requestID))
	}
	for _, a := range identityAttributes(ctx) {
		record.AddAttributes(a)
	}
	m.loggerProvider.Logger(scope).Emit(ctx, record)
}

// failure adapters still accept failure.Operation. narrow against the compiled
// log vocabulary before exporting; a syntactically plausible input is not proof
// that its words were authored. unknown operations use the existing fallback.
func operationID(operation failure.Operation) operationName {
	if name, ok := operationalNames[operation]; ok {
		return name
	}
	return "operational_failure"
}

var operationalNames = func() map[failure.Operation]operationName {
	names := make(map[failure.Operation]operationName)
	for _, words := range []failure.Operation{
		"advance DNS work", "advance certificate work", "authenticate publish run",
		"authenticate device browser", "read admin server status", "list admin relays",
		"drain admin relay", "list maintenance controls", "set maintenance control",
		"read identity context", "list teams", "get team", "list team domains",
		"clean up routing history", "clean up guest private state", "expire publish runs",
		"renew relay lease", "serve relay publisher", "forward through relay",
		"serve relay QUIC session", "clean up service audit", "renew ingress lease",
		"report ingress recovery", "close ingress relay session",
		"read ingress public URL", "serve ingress connection", "refresh service port capacity",
		"serve standalone relay publisher", "clean up ephemeral public URLs",
		"read feedback thread", "encode feedback thread", "list feedback threads",
		"encode feedback list", "append feedback event", "encode feedback event",
		"list feedback thread events", "encode feedback events", "watch feedback events",
		"read watched feedback", "encode watched feedback", "replace visitor access",
		"read share public URL", "create share", "check guest IP", "create guest share",
		"list shares", "list team shares", "revoke share", "read share", "enable share access",
		"read publisher shares", "read preview team access", "redeem share",
		"select publish-run traffic limits", "verify feedback reviewer", "encode feedback report",
		"list page feedback", "encode page feedback", "encode reviewer feedback",
		"encode reviewer feedback thread", "list reviewer feedback events",
		"encode reviewer feedback events", "read reviewer feedback", "service audit",
		"read publisher editor", "create preview", "read preview public URL",
		"add preview public URL", "read preview", "create certificate issuance",
		"get certificate issuance", "get project public metadata", "read browser preview",
		"read browser public URL", "create browser nonce", "create browser binding",
		"select company browser sign-in", "start browser sign-in", "discover browser identity provider",
		"consume browser sign-in", "verify browser identity", "save browser sign-in",
		"authorize browser identity", "read signed-in browser public URL", "redeem browser handoff",
		"check browser access", "create demo feedback", "read team preview public URL",
		"set preview team access", "list public URLs", "create public URL", "read public URL for update",
		"update public URL", "get public URL", "read public URL for deletion", "delete public URL",
		"read public URL for publish run", "read created publish run", "heartbeat publish run",
		"mark public URL certificate installed", "mark publish run ready", "close publish run",
		"resolve website identity", "accept website invitation", "preview website invitation",
		"create team", "list team memberships", "set membership role", "remove membership",
		"list team invitations", "create team invitation", "revoke team invitation", "accept invitation",
		"claim team domain", "set team default domain", "release team domain", "authorize workload session",
		"read feedback author policy", "set feedback author policy",
		"renew private publisher", "renew publisher lease", "renew publisher",
	} {
		name := strings.ToLower(strings.Join(strings.Fields(string(words)), "_"))
		names[words] = operationName(name)
	}
	return names
}()
