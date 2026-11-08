package config

import (
	"strings"
	"testing"
)

func TestValidKubernetesName(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
		valid bool
	}{
		{"single letter", "a", true},
		{"single digit", "0", true},
		{"hyphenated", "orders-worker-1", true},
		{"subdomain", "orders.worker", true},
		{"numeric labels", "1.2", true},
		{"63 character label", strings.Repeat("a", 63), true},
		{"64 character label", strings.Repeat("a", 64), true},
		{"253 character label", strings.Repeat("a", 253), true},
		{"253 character subdomain", strings.Repeat("a", 64) + "." + strings.Repeat("b", 188), true},
		{"empty", "", false},
		{"uppercase", "Orders", false},
		{"uppercase label", "orders.Worker", false},
		{"underscore", "orders_1", false},
		{"leading hyphen", "-orders", false},
		{"trailing hyphen", "orders-", false},
		{"leading dot", ".orders", false},
		{"trailing dot", "orders.", false},
		{"empty label", "orders..worker", false},
		{"label leading hyphen", "orders.-worker", false},
		{"label trailing hyphen", "orders-.worker", false},
		{"path", "../orders", false},
		{"wildcard", "*.orders", false},
		{"leading space", " orders", false},
		{"trailing space", "orders ", false},
		{"newline", "orders\n", false},
		{"non ASCII", "ordérs", false},
		{"254 character label", strings.Repeat("a", 254), false},
		{"254 character subdomain", strings.Repeat("a", 64) + "." + strings.Repeat("b", 189), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := ValidKubernetesName(test.value); got != test.valid {
				t.Fatalf("ValidKubernetesName(%q) = %t, want %t", test.value, got, test.valid)
			}
		})
	}
}

func TestKubernetesWorkloadBlockAndNames(t *testing.T) {
	c := TNL{Services: Services{"db": {PublisherGroup: new("production")}}, Workloads: map[string]Workload{"app": {Kubernetes: &WorkloadKubernetes{ServiceAccount: "orders.worker"}, Services: []string{"db"}}}}
	for _, name := range []string{"orders.worker", strings.Repeat("a", 64), strings.Repeat("a", 253)} {
		c.Workloads["app"].Kubernetes.ServiceAccount = name
		if err := ValidateWorkloads(c); err != nil {
			t.Fatalf("valid Kubernetes service account %q rejected: %v", name, err)
		}
	}
	for _, namespace := range []string{"production.apps", strings.Repeat("a", 64)} {
		c.Workloads["app"].Kubernetes.Namespace = namespace
		if ValidateWorkloads(c) == nil {
			t.Fatalf("invalid Kubernetes namespace %q accepted", namespace)
		}
	}
	c.Workloads["app"].Kubernetes.Namespace = ""
	p := c.Workloads["app"]
	p.Google = &WorkloadGoogle{ServiceAccount: "112010400000000710080"}
	c.Workloads["app"] = p
	if ValidateWorkloads(c) == nil {
		t.Fatal("mixed provider blocks accepted")
	}
}
