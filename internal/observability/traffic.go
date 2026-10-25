package observability

import (
	"context"

	"github.com/tnldotdev/tnl/internal/region"
	"go.opentelemetry.io/otel/metric"
)

func (m *Metrics) ObserveSTUNBinding(result string) {
	if m == nil {
		return
	}
	switch result {
	case "accepted", "invalid", "capacity", "transport_error":
		m.stunBindings.With(resultDimension(result)).Inc()
	}
}

type RelayTransferDirection string

const (
	RelayVisitorToPublisher RelayTransferDirection = "visitor_to_publisher"
	RelayPublisherToVisitor RelayTransferDirection = "publisher_to_visitor"
)

// ObserveRelayRegionalTransfer counts only successfully written bytes. relay is
// the sole accounting boundary, so ingress and publisher do not duplicate them.
func (m *Metrics) ObserveRelayRegionalTransfer(ctx context.Context, ingress, relay region.Code, direction RelayTransferDirection, bytes int64) {
	if m == nil || bytes <= 0 || direction != RelayVisitorToPublisher && direction != RelayPublisherToVisitor {
		return
	}
	ingressCode, ingressOK := region.Parse(string(ingress))
	relayCode, relayOK := region.Parse(string(relay))
	if !ingressOK || !relayOK || ingressCode != ingress || relayCode != relay {
		return
	}
	m.regionalForwardedBytes.instrument.Add(ctx, float64(bytes), metric.WithAttributeSet(metricDimensions(
		m.regionalForwardedBytes.keys, IngressRegion.Dimension(string(ingress)), RelayRegion.Dimension(string(relay)), Direction.Dimension(string(direction)),
	)))
}

func (m *Metrics) ObserveTrafficAdmission(stage, result string) {
	switch stage {
	case "source", "ordinary", "pending", "promotion", "bytes":
	default:
		return
	}
	switch result {
	case "accepted", "capacity", "stale", "expired", "bandwidth", "invalid":
	default:
		return
	}
	m.trafficAdmissions.With(Operation.Dimension(operationName(stage)), resultDimension(result)).Inc()
}
