package observability

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// ControlOperation starts before database work so driver spans inherit the
// operation, rather than constructing a disconnected span after completion.
func ControlOperation(ctx context.Context, operation ServerOperation) (context.Context, func(error)) {
	if operation < OpCreatePublishRun || operation > OpPublisherRuntimeInvalid {
		return ctx, func(error) {}
	}
	name := operation.operation()
	m := FromContext(ctx)
	started := time.Now()
	ctx, end := Start(ctx, name)
	var once sync.Once
	return ctx, func(err error) {
		once.Do(func() {
			if m != nil {
				m.controlOperations.With(Operation.Dimension(name), OutcomeKey.Dimension(ErrorOutcome(err))).ObserveContext(ctx, time.Since(started).Seconds())
			}
			end(err)
		})
	}
}

// WorkerAttempt is finite asynchronous work. link a scheduling span when one
// exists without pretending a later worker iteration is part of that request.
// no scheduling context, SQL, work payload, or errors are retained between runs.
func WorkerAttempt(ctx context.Context, operation operationName) (context.Context, func(error)) {
	options := []trace.SpanStartOption{trace.WithNewRoot()}
	if parent := trace.SpanContextFromContext(ctx); parent.IsValid() {
		options = append(options, trace.WithLinks(trace.Link{SpanContext: parent}))
	}
	return Start(ctx, operation, options...)
}

// MarkReason accepts only closed domain classifications, never cause text.
func MarkReason(ctx context.Context, reason DomainReason) {
	if value := reason.String(); value != "" {
		trace.SpanFromContext(ctx).SetAttributes(Reason.String(value))
	}
}

// AuthenticatedServerScope is called only after state has verified the exact
// credential. IDs and protocol stay on this span and explicitly scoped callers.
func AuthenticatedServerScope(ctx context.Context, identity Identity, fields Fields) context.Context {
	ctx = WithFields(ReplaceIdentity(ctx, identity), fields)
	trace.SpanFromContext(ctx).SetAttributes(append(identityAttributes(ctx), fieldAttributes(ctx)...)...)
	return ctx
}

type certificateKindKey struct{}

func WithCertificateKind(ctx context.Context, kind string) context.Context {
	if kind != "public_url" && kind != "service" && kind != "relay" {
		return ctx
	}
	trace.SpanFromContext(ctx).SetAttributes(CertificateKind.String(kind))
	return context.WithValue(ctx, certificateKindKey{}, kind)
}

func CertificateDNSKind(ctx context.Context) string {
	if kind, _ := ctx.Value(certificateKindKey{}).(string); kind == "service" {
		return "service_challenge"
	}
	return "public_url_challenge"
}

func ObservePublisherRuntime(ctx context.Context, action string, outcome Outcome, reason DomainReason, elapsed time.Duration) {
	switch action {
	case "inspect", "start", "renew", "stop":
	default:
		return
	}
	m := FromContext(ctx)
	if m == nil {
		return
	}
	attrs := append(Attributes(ctx, TeamID, EnvironmentID, PublisherGroupID, PublisherIdentityID, DeploymentID, ReplicaKey), Operation.Value(operationName(action)), OutcomeKey.Value(outcome))
	if value := reason.String(); value != "" {
		attrs = append(attrs, Reason.String(value))
	}
	m.publisherruntime.instrument.Record(ctx, elapsed.Seconds(), metric.WithAttributes(attrs...))
}

func (m *Metrics) completedResult(ctx context.Context, name operationName, outcome semanticResult, elapsed time.Duration) (context.Context, func()) {
	now := time.Now()
	ctx, span := m.tracer().Start(ctx, name.String(), trace.WithTimestamp(now.Add(-elapsed)), trace.WithAttributes(append(identityAttributes(ctx), fieldAttributes(ctx)...)...))
	span.SetAttributes(Operation.Value(name))
	return ctx, func() {
		finishSpan(span, outcome)
		span.End(trace.WithTimestamp(now))
	}
}

func (m *Metrics) ObserveDatabaseQueryContext(ctx context.Context, operation DatabaseOperationName, err error, elapsed time.Duration) {
	if m == nil {
		return
	}
	ctx, finish := m.completedOperation(ctx, "database."+operation.operation(), elapsed)
	trace.SpanFromContext(ctx).SetAttributes(Operation.Value(operation.operation()))
	m.databaseQueryDuration.With(Operation.Dimension(operation.operation()), OutcomeKey.Dimension(ErrorOutcome(err))).ObserveContext(ctx, elapsed.Seconds())
	finish(err)
	if err != nil {
		phase := operationName("query")
		switch operation.String() {
		case "begin", "commit", "rollback":
			phase = operation.operation()
		}
		m.databaseFailures.With(Operation.Dimension(phase), OutcomeKey.Dimension(ErrorOutcome(err))).Inc()
	}
}

func (m *Metrics) ObserveDatabaseAcquireContext(ctx context.Context, err error, elapsed time.Duration) {
	if m == nil {
		return
	}
	ctx, finish := m.completedOperation(ctx, "database.acquire", elapsed)
	trace.SpanFromContext(ctx).SetAttributes(Operation.Value("acquire"))
	m.databaseAcquireDuration.With(OutcomeKey.Dimension(ErrorOutcome(err))).ObserveContext(ctx, elapsed.Seconds())
	finish(err)
	if err != nil {
		m.databaseFailures.With(Operation.Dimension("acquire"), OutcomeKey.Dimension(ErrorOutcome(err))).Inc()
	}
}

func (m *Metrics) ObserveDatabaseGuardContext(ctx context.Context, operation DatabaseOperationName, err error, elapsed time.Duration) {
	if m != nil {
		m.databaseGuardDuration.With(Operation.Dimension(operation.operation()), OutcomeKey.Dimension(ErrorOutcome(err))).ObserveContext(ctx, elapsed.Seconds())
	}
}
