package config

import (
	"strings"
	"testing"
	"time"
)

func TestCloudSelectorsAndCIReferences(t *testing.T) {
	text := func(value string) *string { return &value }
	configuration := TNL{Services: Services{
		"cluster": {Protocol: text("kubernetes"), Target: &ServiceTarget{Type: "eks", Cluster: text("development"), Region: text("us-east-1")}},
		"db":      {Protocol: text("postgres"), Target: &ServiceTarget{Type: "rds", Cluster: text("orders"), Region: text("eu-west-1"), Endpoint: text("reader")}},
	}, CI: map[string]CI{"deploy": {GitHub: CIGitHub{Workflow: ".github/workflows/deploy.yml", Ref: "refs/heads/main", Events: []string{"push"}}, Services: []string{"cluster", "db"}}}}
	if err := ValidateTNL(configuration); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []struct {
		name   string
		mutate func(*TNL)
	}{
		{"wrong eks protocol", func(c *TNL) { s := c.Services["cluster"]; s.Protocol = text("http"); c.Services["cluster"] = s }},
		{"rds xor", func(c *TNL) { c.Services["db"].Target.Instance = text("other") }},
		{"instance reader", func(c *TNL) { c.Services["db"].Target.Instance, c.Services["db"].Target.Cluster = text("orders"), nil }},
		{"wildcard resource", func(c *TNL) { c.Services["db"].Target.Cluster = text("orders*") }},
		{"unknown service", func(c *TNL) { p := c.CI["deploy"]; p.Services = []string{"missing"}; c.CI["deploy"] = p }},
		{"workflow wildcard", func(c *TNL) { p := c.CI["deploy"]; p.GitHub.Workflow = ".github/workflows/*.yml"; c.CI["deploy"] = p }},
		{"ref wildcard", func(c *TNL) { p := c.CI["deploy"]; p.GitHub.Ref = "refs/heads/*"; c.CI["deploy"] = p }},
		{"event unsupported", func(c *TNL) { p := c.CI["deploy"]; p.GitHub.Events = []string{"anything"}; c.CI["deploy"] = p }},
		{"duration", func(c *TNL) {
			p := c.CI["deploy"]
			duration := Duration(25 * time.Hour)
			p.MaxDuration = &duration
			c.CI["deploy"] = p
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
			copy.CI = map[string]CI{"deploy": configuration.CI["deploy"]}
			invalid.mutate(&copy)
			if err := ValidateTNL(copy); err == nil || strings.Contains(err.Error(), "orders*") {
				t.Fatalf("invalid selector accepted or leaked: %v", err)
			}
		})
	}
}
