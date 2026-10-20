package observability

import (
	"context"
	"slices"
	"time"

	"go.opentelemetry.io/otel/metric"
)

const PortInventoryFreshness = 90 * time.Second

type PortPoolCapacity struct {
	Pool                                        string
	Configured, Claimed, Quarantined, Available int64
}

type portInventory struct {
	refreshed time.Time
	pools     []PortPoolCapacity
}

// ReplacePortPoolCapacity publishes one successful, complete database snapshot.
// failures retain its timestamp, never renew its freshness or partially replace it.
func (m *Metrics) ReplacePortPoolCapacity(pools []PortPoolCapacity, refreshed time.Time) {
	if m != nil {
		m.portInventory.Store(&portInventory{refreshed: refreshed, pools: slices.Clone(pools)})
	}
}

func (m *Metrics) registerPortInventory() {
	const name = "tnl_control_tcp_port_pool_ports"
	describe(m.meter, name, "Fresh committed port inventory; absent after 90 seconds without refresh. Use maximum across control replicas.", "gauge", nil, "pool", "state")
	_, err := m.meter.Float64ObservableGauge(name, metric.WithFloat64Callback(func(_ context.Context, observer metric.Float64Observer) error {
		snapshot := m.portInventory.Load()
		if snapshot == nil || time.Since(snapshot.refreshed) > PortInventoryFreshness {
			return nil
		}
		for _, pool := range snapshot.pools {
			for state, count := range map[string]int64{"configured": pool.Configured, "claimed": pool.Claimed, "quarantined": pool.Quarantined, "available": pool.Available} {
				observer.Observe(float64(count), metric.WithAttributeSet(metricLabelSet(name, []string{"pool", "state"}, []string{pool.Pool, state})))
			}
		}
		return nil
	}))
	if err != nil {
		panic(err)
	}
	m.gaugeFunc("tnl_control_tcp_port_pool_last_success_timestamp_seconds", "Last complete successful inventory refresh; zero before success. Use maximum across control replicas.", func() float64 {
		if snapshot := m.portInventory.Load(); snapshot != nil {
			return routingTimestamp(snapshot.refreshed)
		}
		return 0
	})
}
