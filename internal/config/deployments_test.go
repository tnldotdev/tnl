package config

import (
	"encoding/json/v2"
	"fmt"
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
	if Protocol(local.Services["web"]) != "http" || TargetType(local.Services["web"]) != "app" || TargetType(local.Services["db"]) != "compose" || len(production.Services) != 1 || Protocol(production.Services["db"]) != "postgres" || TargetType(production.Services["db"]) != "address" || SelectedDeployment(production) != "production" {
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

func TestDeploymentConfigurationStaticFormatsAndUnknownFields(t *testing.T) {
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
	for _, invalid := range []string{
		`{"services":{"db":{"protocol":"postgres","target":{"type":"address","address":"localhost:5432"}}}}`,
		`{"services":{"db":{"protocol":"postgres"}},"deployments":{"production":{"targets":{"db":{"protocol":"mysql","address":"localhost:3306"}}}}}`,
	} {
		var project Project
		if err := json.Unmarshal([]byte(invalid), &project, json.RejectUnknownMembers(true)); err == nil {
			t.Fatal("configuration accepted fields outside their declaration or binding")
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
	if TargetType(web) != "app" || web.Target.Address != nil || !IsPublicService(web) || SelectedDeployment(selected) != "production" {
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

func TestResolvedDeploymentOwnsSettings(t *testing.T) {
	project := deploymentProjectFixture()
	description, domain := "production database", "example.test"
	settings := project.Deployments["production"]
	settings.Description, settings.Domain, settings.Public = &description, &domain, true
	project.Deployments["production"] = settings
	production, err := ResolveDeployment(project, "production")
	if err != nil {
		t.Fatal(err)
	}
	local, err := ResolveDeployment(project, "local")
	if err != nil {
		t.Fatal(err)
	}
	if SelectedDeployment(production) != "production" || production.DeploymentSettings.Description == nil || *production.DeploymentSettings.Description != description || production.DeploymentSettings.Domain == nil || *production.DeploymentSettings.Domain != domain || !production.DeploymentSettings.Public {
		t.Fatal("selection lost its deployment settings")
	}
	if local.DeploymentSettings.Description != nil || local.DeploymentSettings.Domain != nil || local.DeploymentSettings.Public {
		t.Fatal("local selection inherited saved deployment settings")
	}
}

func TestSavedDeploymentKeepsPerServiceExposure(t *testing.T) {
	project := deploymentProjectFixture()
	deployment := project.Deployments["production"]
	deployment.Targets["web"] = DeploymentBinding{ServiceTarget: ServiceTarget{Address: new(Target("http://web.internal:3000"))}, Public: new(true)}
	db := deployment.Targets["db"]
	db.Public = new(false)
	deployment.Targets["db"] = db
	project.Deployments["production"] = deployment
	selected, err := ResolveDeployment(project, "production")
	if err != nil {
		t.Fatal(err)
	}
	if selected.Services["web"].Public == nil || !*selected.Services["web"].Public || selected.Services["db"].Public == nil || *selected.Services["db"].Public || selected.DeploymentSettings.Public {
		t.Fatal("service exposure changed another binding or the deployment default")
	}
}

func TestPublicURLBindingRejectsServiceEndpointExposure(t *testing.T) {
	for _, public := range []bool{false, true} {
		for _, deployment := range []string{"local", "production"} {
			t.Run(fmt.Sprintf("%s/public=%t", deployment, public), func(t *testing.T) {
				project := Project{
					Services: map[string]ServiceDeclaration{"web": {}},
					Deployments: map[string]Deployment{deployment: {Targets: map[string]DeploymentBinding{
						"web": {Tunnel: &Tunnel{}, Public: new(public)},
					}}},
				}
				if err := ValidateProject(project); err == nil {
					t.Fatal("public URL binding silently accepted service endpoint reachability")
				}
				binding := project.Deployments[deployment].Targets["web"]
				binding.Public = nil
				project.Deployments[deployment].Targets["web"] = binding
				if err := ValidateProject(project); err != nil {
					t.Fatal("omitted endpoint reachability changed public URL syntax", err)
				}
			})
		}
		project := Project{
			Services: map[string]ServiceDeclaration{"web": {}},
			Deployments: map[string]Deployment{"production": {Targets: map[string]DeploymentBinding{
				"web": {ServiceTarget: ServiceTarget{Address: new(Target("http://web.internal:3000"))}, Public: new(public)},
			}}},
		}
		if err := ValidateProject(project); err != nil {
			t.Fatal("saved HTTP service lost endpoint reachability", public, err)
		}
	}
}

func TestLocalDeploymentKeepsPerServiceExposure(t *testing.T) {
	project := deploymentProjectFixture()
	local := project.Deployments["local"]
	web := local.Targets["web"]
	web.Tunnel, web.Public = nil, new(true)
	local.Targets["web"] = web
	db := local.Targets["db"]
	db.Public = new(false)
	local.Targets["db"] = db
	project.Deployments["local"] = local
	selected, err := ResolveDeployment(project, "local")
	if err != nil {
		t.Fatal(err)
	}
	if selected.Services["web"].Public == nil || !*selected.Services["web"].Public || IsPublicService(selected.Services["web"]) || selected.Services["db"].Public == nil || *selected.Services["db"].Public {
		t.Fatal("local exposure changed a sibling binding or selected the preview URL lifecycle")
	}
	web.Tunnel = &Tunnel{}
	local.Targets["web"] = web
	if _, err := ResolveDeployment(project, "local"); err == nil {
		t.Fatal("binding selected both public endpoint and preview URL lifecycles")
	}
}

func TestWorkloadSelectionIsCheckedAtTheDeploymentBoundary(t *testing.T) {
	selected := TNL{
		Services: Services{"db": {Protocol: new("postgres"), Target: &ServiceTarget{Type: "address", Address: new(Target("localhost:5432"))}}},
		Workloads: map[string]Workload{"worker": {
			GitHub: &WorkloadGitHub{Workflow: ".github/workflows/test.yml"}, Services: []string{"db"},
		}},
	}
	if err := ValidateWorkloads(selected.Services, selected.Workloads); err != nil {
		t.Fatal("provider validation required unrelated deployment state", err)
	}
	if err := ValidateTNL(selected); err == nil {
		t.Fatal("local selection accepted a workload policy")
	}
	selected.Deployment = "production"
	if err := ValidateTNL(selected); err != nil {
		t.Fatal("remote selection rejected a valid workload policy", err)
	}
}
