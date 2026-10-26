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
	m.ObserveSTUNBinding("accepted")
	m.ObserveSTUNBinding("192.0.2.1")
	m.IncCapacityRejection("pending_source_connections")
	families, err := m.registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == "tnl_ingress_traffic_admissions_total" || family.GetName() == "tnl_relay_stun_bindings_total" {
			if len(family.Metric) != 1 || family.Metric[0].Counter.GetValue() != 1 {
				t.Fatal(family)
			}
		}
		if strings.Contains(family.String(), "url-secret") || strings.Contains(family.String(), "192.0.2.1") {
			t.Fatal("identity escaped metric labels")
		}
	}
}
