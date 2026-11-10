package main

import (
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	"github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestApplyWorkloadCloudSelectors(t *testing.T) {
	group := "production"
	repository := "example/repository"
	protocol := "kubernetes"
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{PublisherGroups: map[string]config.PublisherGroup{group: {}}, Services: config.Services{"cluster": {PublisherGroup: &group, Protocol: &protocol, Target: &config.ServiceTarget{Type: "eks", Region: new("us-east-1"), Cluster: new("production")}}}, Workloads: map[string]config.Workload{"test": {GitHub: &config.WorkloadGitHub{Repository: &repository, Workflow: ".github/workflows/test.yml", Branch: new("main")}, Grants: config.ServiceVisitGrants("cluster")}}}}}
	declaration, err := resolve.Declaration(t.Context(), project.Project, team.Context{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if declaration.Services["cluster"].Target != "" || declaration.Services["cluster"].TargetTls != nil || declaration.Services["cluster"].TargetDiscovery == nil {
		t.Fatal("apply attempted local cloud discovery")
	}
}
