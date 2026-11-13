package config

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"testing"
)

func deploymentProjectFixture() Project {
	return Project{
		Services: map[string]ServiceDeclaration{"web": {}, "db": {Protocol: new("postgres")}},
		Deployments: map[string]Deployment{
			"local": {Targets: map[string]DeploymentBinding{
				"web": {Tunnel: &Tunnel{}},
				"db":  {ServiceTarget: ServiceTarget{Type: "compose", Service: new("database"), Port: new(5432)}},
			}},
			"production": {Targets: map[string]DeploymentBinding{"db": {ServiceTarget: ServiceTarget{Address: new(Target("orders.internal:5432"))}}}},
		},
	}
}

func TestDeploymentConfigurationSeparatesDeclarationsAndBindings(t *testing.T) {
	project := deploymentProjectFixture()
	local, err := ResolveDeployment(project, "local")
	if err != nil {
		t.Fatal(err)
	}
	production, err := ResolveDeployment(project, "production")
	if err != nil {
		t.Fatal(err)
	}
	if Protocol(local.Services["web"]) != "http" || TargetType(local.Services["web"]) != "app" || TargetType(local.Services["db"]) != "compose" || len(production.Services) != 1 || Protocol(production.Services["db"]) != "postgres" || TargetType(production.Services["db"]) != "address" || PublisherGroupName(production.Services["db"]) != "production" {
		t.Fatal("selected configuration mixed service declarations or deployment targets")
	}
	production.Services["db"].Target.Type = "changed"
	if TargetType(local.Services["db"]) != "compose" || project.Deployments["production"].Targets["db"].Type != "" {
		t.Fatal("materializing a deployment changed its source or sibling")
	}
	if _, err := ResolveDeployment(project, "missing"); err == nil {
		t.Fatal("missing deployment silently selected local")
	}
}

func TestDeploymentConfigurationStaticFormatsAndOldShapeRejection(t *testing.T) {
	for _, fixture := range []struct{ name, source string }{
		{"tnl.json", `{"version":1,"tnl":{"services":{"db":{"protocol":"postgres"}},"deployments":{"local":{"targets":{"db":{"address":"127.0.0.1:5432"}}}}}}`},
		{"tnl.yml", "version: 1\ntnl:\n  services:\n    db:\n      protocol: postgres\n  deployments:\n    local:\n      targets:\n        db:\n          address: 127.0.0.1:5432\n"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), fixture.name)
			if err := os.WriteFile(path, []byte(fixture.source), 0600); err != nil {
				t.Fatal(err)
			}
			document, err := LoadDocument(path)
			if err != nil {
				t.Fatal(err)
			}
			resolved, err := ResolveDeployment(*document.TNL, "local")
			if err != nil || string(*resolved.Services["db"].Target.Address) != "127.0.0.1:5432" {
				t.Fatal("static configuration lost its selected target", err)
			}
		})
	}
	for _, old := range []string{
		`{"services":{"db":{"protocol":"postgres","target":{"type":"address","address":"localhost:5432"}}}}`,
		`{"publisher_groups":{"production":{}},"services":{"db":{"publisher_group":"production"}}}`,
		`{"services":{"db":{"protocol":"postgres"}},"deployments":{"production":{"targets":{"db":{"protocol":"mysql","address":"localhost:3306"}}}}}`,
	} {
		var project Project
		if err := json.Unmarshal([]byte(old), &project, json.RejectUnknownMembers(true)); err == nil {
			t.Fatal("replaced or duplicated service definition remained supported")
		}
	}
}

func TestDeploymentConfigurationRejectsUnknownBindingsAndLocalServerFacts(t *testing.T) {
	for _, mutate := range []func(*Project){
		func(p *Project) { p.Deployments["production"].Targets["unknown"] = DeploymentBinding{} },
		func(p *Project) { d := p.Deployments["local"]; d.Public = true; p.Deployments["local"] = d },
		func(p *Project) { p.Services["db"] = ServiceDeclaration{Protocol: new("unknown")} },
		func(p *Project) { p.Workloads = map[string]DeploymentWorkload{"app": {Deployment: "local"}} },
	} {
		project := deploymentProjectFixture()
		mutate(&project)
		if err := ValidateProject(project); err == nil {
			t.Fatal("invalid declaration or deployment boundary was accepted")
		}
	}
}

func TestDeploymentConfigurationCapturesWorkloadSelection(t *testing.T) {
	project := deploymentProjectFixture()
	project.Workloads = map[string]DeploymentWorkload{"app": {Deployment: "production", Workload: Workload{GitHub: &WorkloadGitHub{Workflow: ".github/workflows/test.yml"}, Services: []string{"db"}}}}
	local, err := ResolveDeployment(project, "local")
	if err != nil {
		t.Fatal(err)
	}
	production, err := ResolveDeployment(project, "production")
	if err != nil {
		t.Fatal(err)
	}
	if len(local.Workloads) != 0 || len(production.Workloads) != 1 || production.Workloads["app"].Services[0] != "db" {
		t.Fatal("provider policy borrowed another deployment's binding")
	}
	policy := project.Workloads["app"]
	policy.Services = []string{"web"}
	project.Workloads["app"] = policy
	if err := ValidateProject(project); err == nil {
		t.Fatal("provider policy selected an unbound logical service")
	}
}

func TestDeploymentConfigurationPublicAppDoesNotRepeatItsListener(t *testing.T) {
	p := deploymentProjectFixture()
	p.Deployments["production"].Targets["web"] = DeploymentBinding{Tunnel: &Tunnel{Access: &Access{Mode: "restricted"}}}
	selected, err := ResolveDeployment(p, "production")
	if err != nil {
		t.Fatal(err)
	}
	web := selected.Services["web"]
	if TargetType(web) != "app" || web.Target.Address != nil || !IsPublicService(web) || PublisherGroupName(web) != "production" {
		t.Fatal("deployment public app invented a listener or selected a developer namespace")
	}
	p.Deployments["production"].Targets["web"] = DeploymentBinding{Tunnel: &Tunnel{Ephemeral: new(true)}}
	if err := ValidateProject(p); err == nil {
		t.Fatal("named deployment app accepted temporary saved URL settings")
	}
	p.Deployments["production"].Targets["web"] = DeploymentBinding{}
	if err := ValidateProject(p); err == nil {
		t.Fatal("unpublished remote app was accepted without a serving owner")
	}
}
