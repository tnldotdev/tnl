package observability

import (
	"context"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

func (m *Metrics) tracer() trace.Tracer {
	if m == nil || m.tracerProvider == nil {
		return noop.NewTracerProvider().Tracer(scope)
	}
	return m.tracerProvider.Tracer(scope)
}

// Start records a finite, authored operation. callers must not pass paths,
// hostnames, errors or other external input as the name. errors become a fixed
// outcome; raw causes are never recorded as span status or exception events.
func Start(ctx context.Context, name string, options ...trace.SpanStartOption) (context.Context, func(error)) {
	options = append(options, trace.WithAttributes(append(identityAttributes(ctx), fieldAttributes(ctx)...)...))
	ctx, span := FromContext(ctx).tracer().Start(ctx, name, options...)
	span.SetAttributes(Operation.String(name))
	if id, ok := ctx.Value(visitorKey{}).(string); ok {
		Visitor(ctx, id)
	}
	var once sync.Once
	return ctx, func(err error) { once.Do(func() { finishError(span, err); span.End() }) }
}

func finishSpan(span trace.Span, outcome string) {
	result, reason := classifyResult(outcome)
	span.SetAttributes(OutcomeKey.String(string(result)))
	if reason != "" {
		span.SetAttributes(Reason.String(reason))
	}
	if result != Success && result != Canceled {
		span.SetStatus(codes.Error, string(result))
	}
}

// Visitor correlates independent tunnel-hop spans without adding fields to the
// tunnel protocol or treating an external ID as an OTel parent span.
func Visitor(ctx context.Context, id string) {
	if len(id) <= 128 {
		trace.SpanFromContext(ctx).SetAttributes(VisitorConnectionID.String(id))
	}
}

type visitorKey struct{}

func WithVisitor(ctx context.Context, id string) context.Context {
	if len(id) > 128 {
		return ctx
	}
	return context.WithValue(ctx, visitorKey{}, id)
}

// PublisherOperation includes the scoped, authenticated identities in metrics.
// these spans end at the operation boundary, not when the publisher exits.
func PublisherOperation(ctx context.Context, operation string) (context.Context, func(error)) {
	switch operation {
	case "startup", "heartbeat", "connect", "private_startup", "private_heartbeat", "private_connect", "target_connect", "target_tls", "target_preflight", "readiness_probe", "visitor_admission", "visitor_tls", "visitor_negotiation", "target_negotiation", "native_auth", "visitor_authorization", "certificate", "group_lease":
	default:
		return ctx, func(error) {}
	}
	fields, _ := ctx.Value(fieldsKey{}).(Fields)
	switch operation {
	case "visitor_tls", "visitor_negotiation":
		fields.TLSLeg = "visitor"
	case "target_tls", "target_negotiation":
		fields.TLSLeg = "target"
	}
	ctx = WithFields(ctx, fields)
	started := time.Now()
	ctx, end := Start(ctx, "publisher."+operation)
	m := FromContext(ctx)
	var once sync.Once
	return ctx, func(err error) {
		once.Do(func() {
			end(err)
			if m == nil {
				return
			}
			attrs := append(publisherDataAttributes(ctx), Attributes(ctx, TLSLeg, Transport, TransportPreference, ConnectionSlot)...)
			attrs = append(attrs, Operation.String(operation), OutcomeKey.String(durationOutcome(err)))
			m.publisherOperations.Record(ctx, time.Since(started).Seconds(), metric.WithAttributes(attrs...))
		})
	}
}

// completedSpan adapts existing observers which already own a measured interval.
// it makes local operation spans without inventing cross-process parentage.
func (m *Metrics) completedSpan(name, outcome string, elapsed time.Duration) {
	if m == nil || elapsed < 0 {
		return
	}
	now := time.Now()
	_, span := m.tracer().Start(context.Background(), name, trace.WithTimestamp(now.Add(-elapsed)))
	finishSpan(span, outcome)
	span.End(trace.WithTimestamp(now))
}

func (m *Metrics) completedOperation(ctx context.Context, name string, elapsed time.Duration) (context.Context, func(error)) {
	if elapsed < 0 {
		return ctx, func(error) {}
	}
	now := time.Now()
	ctx, span := m.tracer().Start(ctx, name, trace.WithTimestamp(now.Add(-elapsed)), trace.WithAttributes(append(identityAttributes(ctx), fieldAttributes(ctx)...)...))
	return ctx, func(err error) { finishError(span, err); span.End(trace.WithTimestamp(now)) }
}

// OwnedHTTPClient must only wrap a client dedicated to tnl-owned HTTP APIs.
// customer target clients and DNS/CA/identity-provider clients never use it.
// no URL, path, header, body or peer address becomes an attribute.
func OwnedHTTPClient(client *http.Client, surface string) *http.Client {
	if client == nil {
		client = http.DefaultClient
	}
	copy := *client
	base := copy.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	copy.Transport = ownedTransport{base: base, surface: surface}
	return &copy
}

type ownedTransport struct {
	base    http.RoundTripper
	surface string
}

func (t ownedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	m := FromContext(r.Context())
	if m == nil {
		return t.base.RoundTrip(r)
	}
	ctx, span := m.tracer().Start(r.Context(), "tnl."+t.surface+".request", trace.WithSpanKind(trace.SpanKindClient))
	defer span.End()
	r = r.Clone(ctx)
	propagation.TraceContext{}.Inject(ctx, propagation.HeaderCarrier(r.Header))
	response, err := t.base.RoundTrip(r)
	outcome := durationOutcome(err)
	if response != nil {
		span.SetAttributes(HTTPStatus.Int(response.StatusCode))
		switch {
		case response.StatusCode >= 500:
			outcome = "server_error"
		case response.StatusCode == 401 || response.StatusCode == 403:
			outcome = "denied"
		case response.StatusCode >= 400:
			outcome = "client_error"
		}
	}
	if err != nil {
		finishError(span, err)
	} else {
		finishSpan(span, outcome)
	}
	span.SetAttributes(Component.String(t.surface), HTTPMethod.String(httpMethod(r.Method)))
	return response, err
}

func httpMethod(value string) string {
	switch value {
	case "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH":
		return value
	}
	return "_OTHER"
}
