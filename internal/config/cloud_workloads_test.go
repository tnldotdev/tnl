package config

import (
	"strings"
	"testing"
	"time"
)

func TestCloudSelectorsAndWorkloadReferences(t *testing.T) {
	text := func(value string) *string { return &value }
	configuration := TNL{Publishers: map[string]Publisher{"production": {}}, Services: Services{
		"cluster": {Publisher: text("production"), Protocol: text("kubernetes"), Target: &ServiceTarget{Type: "eks", Cluster: text("development"), Region: text("us-east-1")}},
		"db":      {Publisher: text("production"), Protocol: text("postgres"), Target: &ServiceTarget{Type: "rds", Cluster: text("orders"), Region: text("eu-west-1"), Endpoint: text("reader")}},
	}, Workloads: map[string]Workload{"deploy": {Provider: "github", GitHub: &WorkloadGitHub{Workflow: ".github/workflows/deploy.yml", Ref: "refs/heads/main", Events: []string{"push"}}, Services: []string{"cluster", "db"}}}}
	if err := ValidateTNL(configuration); err != nil {
		t.Fatal(err)
	}
	if configuration.Workloads["deploy"].DurationLimit() != time.Hour || configuration.Workloads["deploy"].MaxDuration != nil {
		t.Fatal("workload default must be 1h without changing the declaration")
	}
	policy := configuration.Workloads["deploy"]
	limit := Duration(6 * time.Hour)
	policy.MaxDuration = &limit
	configuration.Workloads["deploy"] = policy
	if err := ValidateTNL(configuration); err != nil {
		t.Fatal("6h must be allowed", err)
	}
	for _, invalid := range []struct {
		name   string
		mutate func(*TNL)
	}{
		{"wrong eks protocol", func(c *TNL) { s := c.Services["cluster"]; s.Protocol = text("http"); c.Services["cluster"] = s }},
		{"rds xor", func(c *TNL) { c.Services["db"].Target.Instance = text("other") }},
		{"instance reader", func(c *TNL) { c.Services["db"].Target.Instance, c.Services["db"].Target.Cluster = text("orders"), nil }},
		{"wildcard resource", func(c *TNL) { c.Services["db"].Target.Cluster = text("orders*") }},
		{"unknown service", func(c *TNL) { p := c.Workloads["deploy"]; p.Services = []string{"missing"}; c.Workloads["deploy"] = p }},
		{"workflow wildcard", func(c *TNL) {
			p := c.Workloads["deploy"]
			p.GitHub.Workflow = ".github/workflows/*.yml"
			c.Workloads["deploy"] = p
		}},
		{"ref wildcard", func(c *TNL) { p := c.Workloads["deploy"]; p.GitHub.Ref = "refs/heads/*"; c.Workloads["deploy"] = p }},
		{"event unsupported", func(c *TNL) {
			p := c.Workloads["deploy"]
			p.GitHub.Events = []string{"anything"}
			c.Workloads["deploy"] = p
		}},
		{"duration", func(c *TNL) {
			p := c.Workloads["deploy"]
			duration := Duration(6*time.Hour + time.Nanosecond)
			p.MaxDuration = &duration
			c.Workloads["deploy"] = p
		}},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			copy := configuration
			copy.Services = Services{}
			for name, service := range configuration.Services {
				target := *service.Target
				service.Target = &target
				copy.Services[name] = service
			}
			copy.Workloads = map[string]Workload{"deploy": configuration.Workloads["deploy"]}
			p := copy.Workloads["deploy"]
			p.GitHub = new(*p.GitHub)
			copy.Workloads["deploy"] = p
			invalid.mutate(&copy)
			if err := ValidateTNL(copy); err == nil || strings.Contains(err.Error(), "orders*") {
				t.Fatalf("invalid selector accepted or leaked: %v", err)
			}
		})
	}
}
