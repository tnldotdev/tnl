package observability

import (
	"strings"
	"testing"
)

func TestTrafficAdmissionLabelsAreBounded(t *testing.T) {
	m := New("ingress")
	m.ObserveTrafficAdmission("promotion", "accepted")
	m.ObserveTrafficAdmission("url-secret", "accepted")
	m.ObserveTrafficAdmission("promotion", "192.0.2.1")
	m.IncCapacityRejection("pending_source_connections")
	families, err := m.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == "tnl_ingress_traffic_admissions_total" {
			if len(family.Metric) != 1 || family.Metric[0].Counter.GetValue() != 1 {
				t.Fatal(family)
			}
		}
		if strings.Contains(family.String(), "url-secret") || strings.Contains(family.String(), "192.0.2.1") {
			t.Fatal("identity escaped metric labels")
		}
	}
}

func TestTrafficAdmissionPreservesDomainResults(t *testing.T) {
	m := New("ingress")
	defer m.Shutdown(t.Context())
	want := map[string]string{"": "success", "capacity": "rejected", "stale": "rejected", "expired": "error", "bandwidth": "rejected", "invalid": "rejected"}
	for _, result := range []string{"accepted", "capacity", "stale", "expired", "bandwidth", "invalid"} {
		m.ObserveTrafficAdmission("promotion", result)
	}
	family := metricFamily(t, m, "tnl_ingress_traffic_admissions_total")
	if len(family.Metric) != len(want) {
		t.Fatalf("traffic result series=%d want=%d", len(family.Metric), len(want))
	}
	for _, point := range family.Metric {
		labels := make(map[string]string)
		for _, label := range point.Label {
			labels[label.GetName()] = label.GetValue()
		}
		reason := labels["tnl_reason"]
		outcome, ok := want[reason]
		if !ok || labels["tnl_outcome"] != outcome || labels["tnl_operation"] != "promotion" || point.Counter.GetValue() != 1 {
			t.Fatalf("traffic result changed: %v", point)
		}
		delete(want, reason)
	}
	if len(want) != 0 {
		t.Fatal("traffic results missing", want)
	}
}
