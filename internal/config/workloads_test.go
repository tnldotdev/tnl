package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWorkloadProviderDeclarationsAndLegacyRejection(t *testing.T) {
	services := Services{"inventory": {PublisherGroup: new("production"), Target: &ServiceTarget{Type: "address", Address: new(Target("localhost:3000"))}}, "models": {PublisherGroup: new("production"), Protocol: new("postgres"), Target: &ServiceTarget{Type: "address", Address: new(Target("localhost:5432"))}}}
	for _, p := range []Workload{
		{GitHub: &WorkloadGitHub{Workflow: ".github/workflows/test.yml"}, Services: []string{"inventory"}},
		{Vercel: &WorkloadVercel{Project: "store", Environment: "production"}, Services: []string{"inventory", "models"}},
		{Fly: &WorkloadFly{App: "store"}, Services: []string{"inventory"}},
		{OIDC: &WorkloadOIDC{Issuer: "https://issuer.example", Claims: map[string]string{"sub": "store"}}, Services: []string{"models"}, Token: &WorkloadToken{File: new("/run/token")}},
	} {
		t.Run(p.Provider(), func(t *testing.T) {
			configuration := TNL{PublisherGroups: map[string]PublisherGroup{"production": {}}, Services: services, Workloads: map[string]Workload{"storefront": p}}
			if err := ValidateTNL(configuration); err != nil {
				t.Fatal("valid provider rejected", err)
			}
			bad := p
			bad.GitHub, bad.Vercel, bad.Fly, bad.OIDC = nil, nil, nil, nil
			configuration.Workloads["storefront"] = bad
			if err := ValidateTNL(configuration); err == nil {
				t.Fatal("unknown provider accepted")
			}
			bad = p
			if p.GitHub == nil {
				bad.GitHub = &WorkloadGitHub{}
			} else {
				bad.Fly = &WorkloadFly{}
			}
			configuration.Workloads["storefront"] = bad
			if err := ValidateTNL(configuration); err == nil {
				t.Fatal("mixed provider policy accepted")
			}
			bad = p
			bad.Services = []string{"missing"}
			configuration.Workloads["storefront"] = bad
			if err := ValidateTNL(configuration); err == nil {
				t.Fatal("unknown service accepted")
			}
			configuration.Workloads["storefront"] = p
			document := Document{Version: new(1), TNL: &configuration}
			b, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "tnl.json")
			if err = os.WriteFile(path, b, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = LoadDocument(path); err != nil {
				t.Fatal("static workload rejected", err)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "tnl.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"tnl":{"ci":{}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDocument(path); err == nil {
		t.Fatal("legacy ci alias accepted")
	}
	for _, policy := range []string{
		`{"provider":"fly","fly":{"app":"worker"},"services":["db"]}`,
		`{"fly":{"app":"worker","app_id":"123"},"services":["db"]}`,
		`{"oidc":{"issuer":"https://issuer.example","claims":{"sub":"worker"}},"token_file":"/run/token","services":["db"]}`,
	} {
		data := `{"version":1,"tnl":{"publisher_groups":{"production":{}},"services":{"db":{"publisher_group":"production","protocol":"postgres","target":{"type":"address","address":"localhost:5432"}}},"workloads":{"worker":` + policy + `}}}`
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadDocument(path); err == nil {
			t.Fatal("removed public workload field accepted")
		}
	}
}

func TestWorkloadSelectorsAndTokenSources(t *testing.T) {
	base := Workload{GitHub: &WorkloadGitHub{Workflow: ".github/workflows/test.yml"}, Services: []string{"db"}}
	if base.GitHub.ExecutionRef("trunk") != "refs/heads/trunk" || base.GitHub.AllowedEvents()[0] != "push" {
		t.Fatal("defaults changed")
	}
	for _, test := range []struct {
		name   string
		change func(*Workload)
		valid  bool
	}{
		{"default", func(*Workload) {}, true},
		{"branch", func(p *Workload) { p.GitHub.Branch = new("main") }, true},
		{"tag", func(p *Workload) { p.GitHub.Tag = new("v1") }, true},
		{"branch with non-final dot", func(p *Workload) { p.GitHub.Branch = new("release./candidate") }, true},
		{"tag with non-final dot", func(p *Workload) { p.GitHub.Tag = new("release./candidate") }, true},
		{"branch ending in dot", func(p *Workload) { p.GitHub.Branch = new("release./candidate.") }, false},
		{"tag ending in dot", func(p *Workload) { p.GitHub.Tag = new("release./candidate.") }, false},
		{"both refs", func(p *Workload) { p.GitHub.Branch, p.GitHub.Tag = new("main"), new("v1") }, false},
		{"empty branch", func(p *Workload) { p.GitHub.Branch = new("") }, false},
		{"empty events", func(p *Workload) { p.GitHub.Events = []string{} }, false},
		{"env", func(p *Workload) { p.Token = &WorkloadToken{Env: new("JOB_TOKEN")} }, true},
		{"file", func(p *Workload) { p.Token = &WorkloadToken{File: new("/run/current.jwt")} }, true},
		{"empty source", func(p *Workload) { p.Token = &WorkloadToken{} }, false},
		{"two sources", func(p *Workload) { p.Token = &WorkloadToken{Env: new("TOKEN"), File: new("token")} }, false},
		{"invalid env", func(p *Workload) { p.Token = &WorkloadToken{Env: new("TOKEN=value")} }, false},
		{"empty file", func(p *Workload) { p.Token = &WorkloadToken{File: new("")} }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := base
			p.GitHub = new(*base.GitHub)
			test.change(&p)
			err := ValidateWorkloads(TNL{Services: Services{"db": {PublisherGroup: new("production")}}, Workloads: map[string]Workload{"worker": p}})
			if (err == nil) != test.valid {
				t.Fatal("unexpected declaration validation", err)
			}
		})
	}
}
