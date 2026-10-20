package observability

import (
	"context"
	"testing"
	"time"
)

func TestPublisherLifecycleInstrumentsRetainKnownProtocolAndBoundedFields(t *testing.T) {
	m := New("publisher")
	defer m.Shutdown(context.Background())
	for _, protocol := range []string{"http", "postgres", "mysql", "tcp", "kubernetes"} {
		ctx := ReplaceIdentity(WithMetrics(t.Context(), m), Identity{ServiceID: "service-" + protocol})
		ctx = WithFields(ctx, Fields{AccessPath: "connector", Exposure: "public"})
		ctx = WithPublisherProtocol(ctx, protocol)
		PublisherLease(ctx, time.Now().Add(time.Minute))
		PublisherReadinessStatus(ctx, true, true, true, time.Now(), time.Now())
		PublisherConnection(ctx, "tls-tcp", false, nil)
	}
	families, err := m.Gather()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"tnl_publisher_lease_expiration_timestamp_seconds":       false,
		"tnl_publisher_readiness_check_timestamp_seconds":        false,
		"tnl_publisher_connection_attempts_total":                false,
		"tnl_publisher_ready":                                    false,
		"tnl_publisher_readiness_last_check_timestamp_seconds":   false,
		"tnl_publisher_readiness_last_success_timestamp_seconds": false,
		"tnl_publisher_target_healthy":                           false,
		"tnl_publisher_configuration_current":                    false,
	}
	for _, family := range families {
		if _, ok := want[family.GetName()]; !ok {
			continue
		}
		seen := map[string]bool{}
		for _, point := range family.Metric {
			labels := map[string]string{}
			for _, label := range point.Label {
				labels[label.GetName()] = label.GetValue()
			}
			if labels["tnl_service_id"] != "service-"+labels["tnl_service_protocol"] || labels["tnl_component"] != "publisher" || labels["tnl_access_path"] != "connector" || labels["tnl_exposure"] != "public" {
				t.Fatal("publisher lifecycle instrument dropped or cleared known bounded scope", family.GetName(), labels)
			}
			seen[labels["tnl_service_protocol"]] = true
		}
		if len(seen) != 5 {
			t.Fatal("publisher lifecycle metric is not reachable for each accepted protocol", family.GetName(), seen)
		}
		want[family.GetName()] = true
	}
	for name, seen := range want {
		if !seen {
			t.Fatal("publisher lifecycle metric did not record", name)
		}
	}
}
