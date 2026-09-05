package observability

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestIngressRoutingMetricsUseOnePassiveSnapshot(t *testing.T) {
	for _, initialized := range []bool{false, true} {
		t.Run(map[bool]string{false: "uninitialized", true: "partial_page"}[initialized], func(t *testing.T) {
			metrics := New("ingress")
			var calls atomic.Int64
			snapshot := IngressRoutingSnapshot{}
			want := map[string]float64{
				"initialized": 0, "caught_up": 0, "last_successful_check_timestamp_seconds": 0,
				"last_caught_up_timestamp_seconds": 0, "latest_observed_revision": 0,
				"applied_revision": 0, "known_revision_backlog": 0,
				"update_failures_total": 0, "resnapshots_total": 0,
			}
			if initialized {
				snapshot = IngressRoutingSnapshot{
					Initialized: true, LastSuccessfulCheck: time.Unix(100, 500_000_000),
					LastCaughtUp: time.Unix(90, 0), LatestRevision: 13, AppliedRevision: 8,
					UpdateFailures: 2, Resnapshots: 1,
				}
				want = map[string]float64{
					"initialized": 1, "caught_up": 0, "last_successful_check_timestamp_seconds": 100.5,
					"last_caught_up_timestamp_seconds": 90, "latest_observed_revision": 13,
					"applied_revision": 8, "known_revision_backlog": 5,
					"update_failures_total": 2, "resnapshots_total": 1,
				}
			}
			metrics.RegisterIngressRouting(func() IngressRoutingSnapshot {
				calls.Add(1)
				return snapshot
			})
			families, err := metrics.Gather()
			if err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 1 {
				t.Fatalf("source reads = %d, want 1", calls.Load())
			}
			for _, family := range families {
				name, ok := strings.CutPrefix(family.GetName(), "tnl_ingress_routing_")
				if !ok {
					continue
				}
				expected, exists := want[name]
				if !exists || len(family.Metric) != 1 || len(family.Metric[0].Label) != 0 {
					t.Fatalf("unexpected routing metric: %v", family)
				}
				metric := family.Metric[0]
				value := metric.GetGauge().GetValue()
				if strings.HasSuffix(name, "_total") {
					if metric.Counter == nil {
						t.Fatalf("%s is not a counter", name)
					}
					value = metric.Counter.GetValue()
				} else if metric.Gauge == nil {
					t.Fatalf("%s is not a gauge", name)
				}
				if value != expected {
					t.Errorf("%s = %v, want %v", name, value, expected)
				}
				delete(want, name)
			}
			if len(want) != 0 {
				t.Fatalf("missing metrics: %v", want)
			}
		})
	}
}
