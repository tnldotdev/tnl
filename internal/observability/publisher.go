package observability

import (
	"context"
	"net"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

func PublisherLease(ctx context.Context, expires time.Time) {
	if m := FromContext(ctx); m != nil {
		m.publisherLease.Record(ctx, routingTimestamp(expires), metric.WithAttributes(identityAttributes(ctx)...))
	}
}

func PublisherReadiness(ctx context.Context, ready bool) {
	if m := FromContext(ctx); m != nil {
		outcome := "not_ready"
		if ready {
			outcome = "ready"
		}
		attrs := append(identityAttributes(ctx), attribute.String("outcome", outcome))
		m.publisherReadiness.Record(ctx, routingTimestamp(time.Now()), metric.WithAttributes(attrs...))
	}
}

func PublisherConnection(ctx context.Context, transport string, preferTCP bool, err error) {
	if m := FromContext(ctx); m != nil {
		if transport != "quic" && transport != "tls-tcp" {
			transport = "none"
		}
		preference := "quic"
		if preferTCP {
			preference = "tls-tcp"
		}
		attrs := append(identityAttributes(ctx), attribute.String("transport", transport), attribute.String("preference", preference), attribute.String("outcome", durationOutcome(err)))
		m.publisherConnectionAttempts.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

// DialTarget observes the connection boundary without recording the address or
// sending trace headers to the customer's target.
func DialTarget(ctx context.Context, network, address string) (net.Conn, error) {
	ctx, finish := PublisherOperation(ctx, "target_connect")
	connection, err := (&net.Dialer{}).DialContext(ctx, network, address)
	finish(err)
	return connection, err
}
