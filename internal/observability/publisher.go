package observability

import (
	"context"
	"net"
	"time"

	"go.opentelemetry.io/otel/metric"
)

func PublisherLease(ctx context.Context, expires time.Time) {
	if m := FromContext(ctx); m != nil {
		m.publisherLease.Record(ctx, routingTimestamp(expires), metric.WithAttributes(publisherDataAttributes(ctx)...))
	}
}

func PublisherReadiness(ctx context.Context, ready bool) {
	if m := FromContext(ctx); m != nil {
		outcome := "not_ready"
		if ready {
			outcome = "ready"
		}
		attrs := append(publisherDataAttributes(ctx), State.String(outcome))
		m.publisherReadiness.Record(ctx, routingTimestamp(time.Now()), metric.WithAttributes(attrs...))
	}
}

func PublisherConnection(ctx context.Context, transport string, preferTCP bool, err error) {
	if m := FromContext(ctx); m != nil {
		if transport != "quic" && transport != "tls-tcp" {
			transport = ""
		}
		preference := "quic"
		if preferTCP {
			preference = "tls-tcp"
		}
		attrs := append(publisherDataAttributes(ctx), TransportPreference.String(preference), OutcomeKey.String(durationOutcome(err)))
		if transport != "" {
			attrs = append(attrs, Transport.String(transport))
		}
		m.publisherConnectionAttempts.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

// WithPublisherProtocol adds known publisher protocol scope without clearing
// the caller's access path, exposure, connection slot, or other bounded fields.
func WithPublisherProtocol(ctx context.Context, protocol string) context.Context {
	fields, _ := ctx.Value(fieldsKey{}).(Fields)
	fields.Component, fields.ServiceProtocol = "publisher", protocol
	return WithFields(ctx, fields)
}

// DialTarget observes the connection boundary without recording the address or
// sending trace headers to the customer's target.
func DialTarget(ctx context.Context, network, address string) (net.Conn, error) {
	ctx, finish := PublisherOperation(ctx, "target_connect")
	connection, err := (&net.Dialer{}).DialContext(ctx, network, address)
	finish(err)
	return connection, err
}
