package observability

import (
	"context"
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

func TestRegionalTransferCountsEachDirectionWithoutUntrustedLabels(t *testing.T) {
	m := New("relay")
	t.Cleanup(func() { _ = m.Shutdown(context.Background()) })
	ctx := t.Context()
	m.ObserveRelayRegionalTransfer(ctx, "sjc", "ord", "visitor_to_publisher", 25)
	m.ObserveRelayRegionalTransfer(ctx, "sjc", "ord", "visitor_to_publisher", 75)
	m.ObserveRelayRegionalTransfer(ctx, "sjc", "ord", "publisher_to_visitor", 250)
	m.ObserveRelayRegionalTransfer(ctx, "not-a-region", "ord", "visitor_to_publisher", 1000)
	m.ObserveRelayRegionalTransfer(ctx, "sjc", "ord", "hostname-secret", 1000)
	families, err := m.Gather()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]float64{}
	for _, family := range families {
		if family.GetName() != "tnl_relay_ingress_transfer_bytes_total" {
			continue
		}
		for _, metric := range family.Metric {
			labels := make(map[string]string)
			for _, label := range metric.Label {
				labels[label.GetName()] = label.GetValue()
			}
			if labels["tnl_ingress_region"] != "sjc" || labels["tnl_relay_region"] != "ord" {
				t.Fatal("unexpected regional transfer labels", labels)
			}
			seen[labels["tnl_direction"]] = metric.GetCounter().GetValue()
		}
	}
	if len(seen) != 2 || seen["visitor_to_publisher"] != 100 || seen["publisher_to_visitor"] != 250 {
		t.Fatal("regional transfer lost a direction or counted invalid labels", seen)
	}
}
