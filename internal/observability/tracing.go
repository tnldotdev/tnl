package observability

import (
	"context"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Identity must come from a verified control response or authenticated state.
// it is scoped to work, never attached to a process resource. run, request and
// visitor IDs deliberately have no metric attribute slot here.
type Identity struct{ TeamID, GroupID, PublisherID, ServiceID, DeploymentID string }
type identityKey struct{}

func WithIdentity(ctx context.Context, identity Identity) context.Context {
	previous, _ := ctx.Value(identityKey{}).(Identity)
	if identity.TeamID == "" {
		identity.TeamID = previous.TeamID
	}
	if identity.GroupID == "" {
		identity.GroupID = previous.GroupID
	}
	if identity.PublisherID == "" {
		identity.PublisherID = previous.PublisherID
	}
	if identity.ServiceID == "" {
		identity.ServiceID = previous.ServiceID
	}
	if identity.DeploymentID == "" {
		identity.DeploymentID = previous.DeploymentID
	}
	if identity == previous {
		return ctx
	}
	return context.WithValue(ctx, identityKey{}, identity)
}
func identityAttributes(ctx context.Context) []attribute.KeyValue {
	id, _ := ctx.Value(identityKey{}).(Identity)
	var attrs []attribute.KeyValue
	for _, item := range [][2]string{{"team_id", id.TeamID}, {"group_id", id.GroupID}, {"publisher_id", id.PublisherID}, {"service_id", id.ServiceID}, {"deployment_id", id.DeploymentID}} {
		if item[1] != "" && len(item[1]) <= 128 {
			attrs = append(attrs, attribute.String(item[0], item[1]))
		}
	}
	return attrs
}

func (m *Metrics) tracer() trace.Tracer {
	if m == nil || m.tracerProvider == nil {
		return noop.NewTracerProvider().Tracer(scope)
	}
	return m.tracerProvider.Tracer(scope)
}

// Start records a finite, authored operation. callers must not pass paths,
// hostnames, errors or other external input as the name. errors become a fixed
// outcome; raw causes are never recorded as span status or exception events.
func Start(ctx context.Context, name string) (context.Context, func(error)) {
	ctx, span := FromContext(ctx).tracer().Start(ctx, name, trace.WithAttributes(identityAttributes(ctx)...))
	if id, ok := ctx.Value(visitorKey{}).(string); ok {
		Visitor(ctx, id)
	}
	var once sync.Once
	return ctx, func(err error) { once.Do(func() { finishSpan(span, durationOutcome(err)); span.End() }) }
}

func finishSpan(span trace.Span, outcome string) {
	span.SetAttributes(attribute.String("outcome", outcome))
	if outcome != "success" && outcome != "canceled" && outcome != "progress" && outcome != "pending" {
		span.SetStatus(codes.Error, outcome)
	}
}

// Visitor correlates independent tunnel-hop spans without adding fields to the
// tunnel protocol or treating an external ID as an OTel parent span.
func Visitor(ctx context.Context, id string) {
	if len(id) <= 128 {
		trace.SpanFromContext(ctx).SetAttributes(attribute.String("visitor_connection_id", id))
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
	case "startup", "heartbeat", "connect", "private_startup", "private_heartbeat", "private_connect", "target_connect", "target_tls", "target_preflight", "readiness_probe", "visitor_admission", "visitor_tls", "certificate", "group_lease":
	default:
		return ctx, func(error) {}
	}
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
			attrs := append(identityAttributes(ctx), attribute.String("operation", operation), attribute.String("outcome", durationOutcome(err)))
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
		span.SetAttributes(attribute.Int("http.response.status_code", response.StatusCode))
		if response.StatusCode >= 400 {
			outcome = "http_error"
		}
	}
	finishSpan(span, outcome)
	return response, err
}
