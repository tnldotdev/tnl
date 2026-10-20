package observability

import (
	"context"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestServerWorkerAttemptLinksSchedulingAndParentsDatabaseWork(t *testing.T) {
	m := New("control")
	defer m.Shutdown(context.Background())
	exporter := tracetest.NewInMemoryExporter()
	m.tracerProvider = trace.NewTracerProvider(trace.WithSyncer(exporter))
	ctx, schedule := Start(WithMetrics(t.Context(), m), "schedule")
	ctx, attempt := WorkerAttempt(ctx, "dns.authority.attempt")
	m.ObserveDatabaseQueryContext(ctx, "LockAppliedProject", nil, time.Millisecond)
	m.ObserveDNSWorkContext(ctx, "authority", "verify", DNSWorkPending, time.Millisecond)
	attempt(context.Canceled)
	schedule(nil)
	spans := exporter.GetSpans()
	if len(spans) != 4 || spans[0].Parent.SpanID() != spans[2].SpanContext.SpanID() || spans[1].Parent.SpanID() != spans[2].SpanContext.SpanID() || spans[2].Parent.IsValid() || len(spans[2].Links) != 1 || spans[2].Links[0].SpanContext.SpanID() != spans[3].SpanContext.SpanID() {
		t.Fatal("worker parentage or scheduling link lost", spans)
	}
	if !containsAttribute(spans[1].Attributes, string(OutcomeKey), "success") || !containsAttribute(spans[1].Attributes, string(Reason), "pending") {
		t.Fatal("DNS pending is successful progress", spans[1])
	}
}

func TestPortInventoryRemovesDisappearedPoolsAndExpiresWithoutRefreshingTimestamp(t *testing.T) {
	m := New("control")
	defer m.Shutdown(context.Background())
	old := time.Now().Add(-PortInventoryFreshness - time.Second)
	m.ReplacePortPoolCapacity([]PortPoolCapacity{{Pool: "old", Configured: 3}}, time.Now())
	if !strings.Contains(metricsText(t, m), `tnl_ingress_pool="old"`) {
		t.Fatal("initial inventory absent")
	}
	m.ReplacePortPoolCapacity([]PortPoolCapacity{{Pool: "current", Configured: 2}}, time.Now())
	text := metricsText(t, m)
	if strings.Contains(text, `tnl_ingress_pool="old"`) || !strings.Contains(text, `tnl_ingress_pool="current"`) {
		t.Fatal("inventory was not replaced atomically", text)
	}
	m.ReplacePortPoolCapacity([]PortPoolCapacity{{Pool: "current", Configured: 2}}, old)
	text = metricsText(t, m)
	if strings.Contains(text, `tnl_ingress_pool="current"`) {
		t.Fatal("expired inventory still claims capacity")
	}
	if got := metricFamily(t, m, "tnl_control_tcp_port_pool_last_success_timestamp_seconds").Metric[0].GetGauge().GetValue(); got != routingTimestamp(old) {
		t.Fatal("scrape renewed inventory freshness", got)
	}
	m.ReplacePortPoolCapacity(nil, time.Now())
	if strings.Contains(metricsText(t, m), `tnl_ingress_pool=`) {
		t.Fatal("empty inventory retained a pool")
	}
}
