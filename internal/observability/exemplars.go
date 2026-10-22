package observability

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/exemplar"
)

// views reject these attributes as metric dimensions. the SDK otherwise saves
// them in exemplar filtered_attributes, bypassing the same allowlist. keep the
// normal reservoir, value, timestamp and trace IDs without retaining that input.
type correlationReservoir struct{ exemplar.Reservoir }

func (r correlationReservoir) Offer(ctx context.Context, at time.Time, value exemplar.Value, _ []attribute.KeyValue) {
	r.Reservoir.Offer(ctx, at, value, nil)
}

func correlationOnlyReservoir(aggregation sdkmetric.Aggregation) exemplar.ReservoirProvider {
	provider := sdkmetric.DefaultExemplarReservoirProviderSelector(aggregation)
	return func(attrs attribute.Set) exemplar.Reservoir {
		return correlationReservoir{provider(attrs)}
	}
}
