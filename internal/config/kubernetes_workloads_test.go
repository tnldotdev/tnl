package config

import "testing"

func TestKubernetesWorkloadBlockAndNames(t *testing.T) {
	c := TNL{Services: Services{"db": {PublisherGroup: new("production")}}, Workloads: map[string]Workload{"app": {Kubernetes: &WorkloadKubernetes{ServiceAccount: "orders.worker"}, Services: []string{"db"}}}}
	if err := ValidateWorkloads(c); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "../orders", "Orders", "orders_1", "orders.", "-orders"} {
		if ValidKubernetesName(name) {
			t.Fatal("invalid Kubernetes resource name accepted", name)
		}
	}
	p := c.Workloads["app"]
	p.Google = &WorkloadGoogle{ServiceAccount: "112010400000000710080"}
	c.Workloads["app"] = p
	if ValidateWorkloads(c) == nil {
		t.Fatal("mixed provider blocks accepted")
	}
}
