package observability

import "testing"

func TestServiceAuditCountersHaveOnlyFixedResults(t *testing.T) {
	m := New("ingress")
	m.ServiceAuditCount("dropped", 7)
	m.ServiceAuditCount("retry", 2)
	m.ServiceAuditCount("secret-url-or-identity", 1)
	families, err := m.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "tnl_service_audit_events_total" {
			continue
		}
		if len(family.Metric) != 6 {
			t.Fatalf("unexpected audit labels: %d", len(family.Metric))
		}
		for _, metric := range family.Metric {
			if metric.Label[0].GetValue() == "dropped" && metric.Counter.GetValue() != 7 {
				t.Fatal("dropped counter lost aggregate count")
			}
		}
		return
	}
	t.Fatal("audit counters are not publicly registered")
}
