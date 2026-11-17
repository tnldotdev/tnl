package observability

import (
	"context"
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
	metrics.ObserveVisitor("private-hostname-secret")
	metrics.ObserveRelayStreamRejection("private-connection-secret")
	metrics.ObserveDNSWork("authority", "verify", "pending", time.Millisecond)
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

func TestOperationDurationsUseFixedRoleLabels(t *testing.T) {
	metrics := New("standalone")
	for _, operation := range []ServerOperation{
		OpCreateServiceRun, OpIngressRegister, OpRelayDisconnectPublisherConnection,
	} {
		metrics.ObserveOperationContext(t.Context(), operation, nil, time.Millisecond)
	}
	metrics.ObserveOperationContext(t.Context(), ServerOperation(255), nil, time.Millisecond)
	for _, test := range []struct {
		name      string
		operation string
	}{
		{"tnl_control_operation_duration_seconds", "CreateServiceRun"},
		{"tnl_ingress_operation_duration_seconds", "IngressRegister"},
		{"tnl_relay_operation_duration_seconds", "RelayDisconnectPublisherConnection"},
	} {
		family := metricFamily(t, metrics, test.name)
		if len(family.Metric) != 1 || family.Metric[0].GetHistogram().GetSampleCount() != 1 {
			t.Fatalf("%s samples = %v", test.name, family.Metric)
		}
		found := false
		for _, label := range family.Metric[0].Label {
			if label.GetName() == "tnl_operation" && label.GetValue() == test.operation {
				found = true
			}
		}
		if !found {
			t.Errorf("%s did not record %s", test.name, test.operation)
		}
	}
}

func TestServiceRunAndRelayMetricsHaveNoRetiredFamiliesOrKindLabels(t *testing.T) {
	metrics := New("standalone")
	metrics.ObserveServiceRunReady()
	metrics.ObserveServiceRunReadiness("ready", time.Millisecond, time.Second)
	metrics.ObserveRecoveryDuration(time.Second)
	metrics.ObserveRelayTransfer(7, 11, nil)
	metrics.ObserveCleanup("service_runs", 2, false, nil)
	metrics.ObserveCleanup("expired_publish_runs", 1, false, nil)

	families, err := metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if strings.Contains(family.GetName(), "public_url") || strings.Contains(family.GetName(), "publish_run") {
			t.Fatalf("retired metric family %s", family.GetName())
		}
		for _, point := range family.Metric {
			for _, label := range point.Label {
				if label.GetName() == "tnl_service_kind" || strings.Contains(label.GetValue(), "public_url") ||
					label.GetValue() == "expired_publish_runs" {
					t.Fatalf("retired metric dimension: %s %v", family.GetName(), label)
				}
			}
		}
	}
	if got := metricFamily(t, metrics, "tnl_control_service_runs_ready_total").Metric[0].GetCounter().GetValue(); got != 1 {
		t.Fatalf("service run first-ready count=%g", got)
	}
	if got := metricFamily(t, metrics, "tnl_control_service_recovery_duration_seconds").Metric[0].GetHistogram().GetSampleCount(); got != 1 {
		t.Fatalf("service recovery observations=%d", got)
	}
	if got := metricFamily(t, metrics, "tnl_relay_forwarded_bytes_total").Metric; len(got) != 2 {
		t.Fatalf("relay byte directions=%d", len(got))
	}
	if got := metricFamily(t, metrics, "tnl_control_cleanup_items_total").Metric[0].GetCounter().GetValue(); got != 2 {
		t.Fatalf("service run cleanup items=%g", got)
	}
}

func TestCertificateAndDNSKindsRejectRetiredPublicURLWork(t *testing.T) {
	metrics := New("control")
	ctx := WithCertificateKind(t.Context(), "public_url")
	if ctx != t.Context() || CertificateDNSKind(ctx) != "" {
		t.Fatal("retired certificate work acquired a DNS challenge kind")
	}
	if got := CertificateDNSKind(WithCertificateKind(context.Background(), "service")); got != "service_challenge" {
		t.Fatal("service certificate lost its DNS challenge kind", got)
	}
	metrics.ObserveCertificateClaim("public_url", CertificateClaimed)
	metrics.ObserveCertificateOrder("public_url", "managed", "exact")
	metrics.ObserveCertificateTransition("public_url", "available")
	metrics.ObserveDNSTransition("public_url", "published")
	metrics.ObserveDNSWork("public_url_challenge", "provider", DNSWorkSuccess, time.Second)
	for _, name := range []string{
		"tnl_control_certificate_claims_total", "tnl_control_certificate_orders_total",
		"tnl_control_certificate_transitions_total", "tnl_control_dns_transitions_total",
		"tnl_control_dns_work_duration_seconds",
	} {
		families, err := metrics.Gather()
		if err != nil {
			t.Fatal(err)
		}
		for _, family := range families {
			if family.GetName() == name && len(family.Metric) != 0 {
				t.Fatalf("retired work recorded %s", name)
			}
		}
	}
}
