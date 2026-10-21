package observability

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryMetricDimensionsAreFixedAndCacheSuccessIsNotExtended(t *testing.T) {
	m := New("publisher")
	defer m.Shutdown(context.Background())
	ctx := ReplaceIdentity(WithMetrics(t.Context(), m), Identity{TeamID: "secret-team", ServiceID: "secret-service"})
	TargetDiscovery(ctx, "eks", "kubernetes", "success", time.Second)
	TargetDiscovery(ctx, "rds", "postgres", "secret-resource-arn", time.Second)
	TargetDiscovery(ctx, "secret-kind", "mysql", "success", time.Second)
	TargetDiscoveryCache(ctx, "eks", "kubernetes", "last_success", time.Unix(100, 0))
	text := metricsText(t, m)
	for _, value := range []string{"secret", "cloud_region", "resource_id"} {
		if strings.Contains(text, value) {
			t.Fatal("uncontrolled discovery dimension exported")
		}
	}
	for _, value := range []string{`tnl_target_provider="aws"`, `tnl_target_type="eks"`, `tnl_service_protocol="kubernetes"`, `tnl_state="last_success"`, `tnl_target_discovery_outcome="unavailable"`} {
		if !strings.Contains(text, value) {
			t.Fatal("missing discovery dimension", value)
		}
	}
	if !strings.Contains(text, "tnl_target_discovery_last_success_timestamp_seconds{") || !strings.Contains(text, "} 100\n") {
		t.Fatal("failed refresh advanced success timestamp")
	}
}
