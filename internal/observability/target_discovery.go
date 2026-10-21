package observability

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/trace"
)

func validDiscovery(kind, protocol string) bool {
	return kind == "eks" && protocol == "kubernetes" || kind == "rds" && (protocol == "postgres" || protocol == "mysql")
}

// TargetDiscovery accepts only compiled low-cardinality classes. selectors,
// ARNs, resource IDs, hosts, regions and SDK response text are never dimensions.
func TargetDiscovery(ctx context.Context, kind, protocol, result string, duration time.Duration) {
	if !validDiscovery(kind, protocol) {
		return
	}
	switch result {
	case "success", "permission", "authentication", "not_found", "not_ready", "unavailable", "metadata", "changed":
	default:
		result = "unavailable"
	}
	if m := FromContext(ctx); m != nil {
		parsed, _ := ParseProtocol(protocol)
		m.targetDiscovery.With(targetProvider.Dimension("aws"), targetType.Dimension(kind), ServiceProtocol.Dimension(parsed), targetDiscoveryOutcome.Dimension(result)).Observe(duration.Seconds())
	}
}

// TargetDiscoveryIdentity is trace-only correlation for validated metadata.
// selectors, network endpoints and provider response bodies are excluded.
func TargetDiscoveryIdentity(ctx context.Context, arn, resourceID string) {
	if len(arn) == 0 || len(arn) > 512 || len(resourceID) == 0 || len(resourceID) > 256 {
		return
	}
	trace.SpanFromContext(ctx).SetAttributes(targetResourceARN.String(arn), targetResourceID.String(resourceID))
}

func TargetDiscoveryCache(ctx context.Context, kind, protocol, state string, success time.Time) {
	if !validDiscovery(kind, protocol) {
		return
	}
	switch state {
	case "fresh", "last_success", "stale", "failed":
	default:
		return
	}
	if m := FromContext(ctx); m != nil {
		parsed, _ := ParseProtocol(protocol)
		dimensions := []Dimension{targetProvider.Dimension("aws"), targetType.Dimension(kind), ServiceProtocol.Dimension(parsed)}
		m.targetDiscoveryCache.With(append(dimensions, stateDimension(state))...).Inc()
		m.targetDiscoverySuccess.With(dimensions...).Set(routingTimestamp(success))
	}
}
