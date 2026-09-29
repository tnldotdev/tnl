package observability

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
)

func metricFamily(t *testing.T, metrics *Metrics, name string) *dto.MetricFamily {
	t.Helper()
	families, err := metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == name {
			return family
		}
	}
	t.Fatalf("missing metric %s", name)
	return nil
}

func TestLeaseExpiryMetricsUseLocalMemory(t *testing.T) {
	ingress := New("ingress")
	var calls atomic.Int32
	expires := time.Unix(100, 0)
	ingress.RegisterIngressLease(func() time.Time { calls.Add(1); return expires })
	if got := metricFamily(t, ingress, "tnl_ingress_lease_expiration_timestamp_seconds").Metric[0].GetGauge().GetValue(); got != 100 || calls.Load() != 1 {
		t.Fatalf("ingress expiration=%g, snapshot calls=%d", got, calls.Load())
	}
	relay := New("standalone")
	relay.SetRelayLeaseExpiry("one", time.Unix(200, 0))
	relay.SetRelayLeaseExpiry("two", time.Unix(150, 0))
	if got := metricFamily(t, relay, "tnl_relay_earliest_lease_expiration_timestamp_seconds").Metric[0].GetGauge().GetValue(); got != 150 {
		t.Fatalf("earliest expiration=%g, want 150", got)
	}
	relay.SetRelayLeaseExpiry("two", time.Time{})
	if got := metricFamily(t, relay, "tnl_relay_earliest_lease_expiration_timestamp_seconds").Metric[0].GetGauge().GetValue(); got != 200 {
		t.Fatalf("expiration after clearing second relay=%g, want 200", got)
	}
	relay.SetRelayCertificateExpiry("one", time.Unix(300, 0))
	if got := metricFamily(t, relay, "tnl_relay_transport_certificate_expiration_timestamp_seconds").Metric[0].GetGauge().GetValue(); got != 300 {
		t.Fatalf("certificate expiry=%g, want 300", got)
	}
}

func TestBackgroundLabelsAreClosed(t *testing.T) {
	metrics := New("standalone")
	metrics.ObserveDNSWork("secret", "provider", "error", time.Second)
	metrics.ObserveDNSWork("authority", "secret", "error", time.Second)
	metrics.ObserveDNSTransition("authority", "secret")
	metrics.ObserveUsageWork("secret", "error")
	metrics.ObserveVisitor("private-hostname-secret")
	metrics.ObserveRelayStreamRejection("private-connection-secret")
	metrics.ObserveDNSWork("authority", "verify", "pending", time.Millisecond)
	metrics.ObserveUsageWork("finalize", "error")
	metrics.ObserveCleanup("routing_prune", 0, true, nil)
	families, err := metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if strings.Contains(label.GetValue(), "secret") {
					t.Fatalf("unbounded metric label: %s %v", family.GetName(), label)
				}
			}
		}
	}
	if got := metricFamily(t, metrics, "tnl_ingress_visitor_connections_total").Metric[0].GetCounter().GetValue(); got != 1 {
		t.Fatalf("unexpected visitor fallback count=%g", got)
	}
}
