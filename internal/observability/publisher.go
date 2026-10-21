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
		outcome := StateNotReady
		if ready {
			outcome = StateReady
		}
		attrs := append(publisherDataAttributes(ctx), State.Value(outcome))
		m.publisherReadiness.Record(ctx, routingTimestamp(time.Now()), metric.WithAttributes(attrs...))
	}
}

func PublisherConnection(ctx context.Context, transport string, preferTCP bool, err error) {
	if m := FromContext(ctx); m != nil {
		if transport != "quic" && transport != "tls-tcp" {
			transport = ""
		}
		preference := TransportQUIC
		if preferTCP {
			preference = TransportTLSTCP
		}
		attrs := append(publisherDataAttributes(ctx), TransportPreference.Value(preference), OutcomeKey.Value(ErrorOutcome(err)))
		if transport != "" {
			parsed, _ := ParseTransport(transport)
			attrs = append(attrs, Transport.Value(parsed))
		}
		m.publisherConnectionAttempts.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

// WithPublisherProtocol adds known publisher protocol scope without clearing
// the caller's access path, exposure, connection slot, or other bounded fields.
func WithPublisherProtocol(ctx context.Context, protocol string) context.Context {
	fields, _ := ctx.Value(fieldsKey{}).(Fields)
	fields.Component = "publisher"
	fields.ServiceProtocol, _ = ParseProtocol(protocol)
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
