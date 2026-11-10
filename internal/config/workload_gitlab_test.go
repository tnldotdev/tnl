package config

import "testing"

func TestGitLabWorkloadDefaultsAndConstraints(t *testing.T) {
	g := WorkloadGitLab{}
	if !g.valid() || g.Origin() != "https://gitlab.com" || g.Source() != "push" || g.ExecutionRef("trunk") != "refs/heads/trunk" {
		t.Fatal("GitLab defaults changed")
	}
	for _, change := range []func(*WorkloadGitLab){
		func(g *WorkloadGitLab) { g.Project = "group/../project" },
		func(g *WorkloadGitLab) { g.Server = "http://gitlab.example" },
		func(g *WorkloadGitLab) { g.Server = "https://gitlab.example/path" },
		func(g *WorkloadGitLab) { g.Server = "https://user:private@gitlab.example" },
		func(g *WorkloadGitLab) { g.Branch, g.Tag = new("main"), new("release") },
		func(g *WorkloadGitLab) { g.Branch = new("*") },
		func(g *WorkloadGitLab) { g.PipelineSource = "*" },
		func(g *WorkloadGitLab) { g.Environment = "preview*" },
	} {
		bad := g
		change(&bad)
		if bad.valid() {
			t.Fatal("invalid GitLab configuration accepted")
		}
	}
	c := TNL{Services: Services{"db": {PublisherGroup: new("production")}}, Workloads: map[string]Workload{"deploy": {GitLab: &g, Grants: ServiceVisitGrants("db")}}}
	if err := ValidateWorkloads(c); err != nil {
		t.Fatal(err)
	}
	p := c.Workloads["deploy"]
	p.Google = &WorkloadGoogle{ServiceAccount: "112010400000000710080"}
	c.Workloads["deploy"] = p
	if ValidateWorkloads(c) == nil {
		t.Fatal("multiple providers accepted")
	}
}
