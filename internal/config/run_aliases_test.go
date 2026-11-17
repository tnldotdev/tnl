package config

import (
	"strings"
	"testing"
)

func TestRunAliasParentValidationAndDeploymentResolution(t *testing.T) {
	for _, parent := range []string{"", "example.test", "preview.example.test"} {
		project := Project{Services: map[string]ServiceDeclaration{"web": {}}, Deployments: map[string]Deployment{
			"production": {Targets: map[string]DeploymentBinding{"web": {RunAliasParent: &parent}}},
		}}
		resolved, err := ResolveDeployment(project, "production")
		if err != nil || resolved.Services["web"].RunAliasParent == nil || *resolved.Services["web"].RunAliasParent != parent {
			t.Fatal("deployment lost an explicit alias parent", parent, err)
		}
		if resolved.Services["web"].Public != nil {
			t.Fatal("alias setting enabled public reachability")
		}
	}
	for _, parent := range []string{"*.example.test", "Example.test", "example.test.", "https://example.test", "example.test:443", " example.test", strings.Repeat("a.", 112) + "test"} {
		if err := ValidateTNL(TNL{Services: Services{"web": {RunAliasParent: &parent}}}); err == nil {
			t.Fatal("invalid alias parent accepted", parent)
		}
	}
	if err := ValidateTNL(TNL{Services: Services{"db": {
		Protocol: new("tcp"), Target: &ServiceTarget{Type: "address", Address: new(Target("localhost:3000"))},
		RunAliasParent: new("example.test"),
	}}}); err == nil {
		t.Fatal("non-HTTP service accepted run aliases")
	}
}
