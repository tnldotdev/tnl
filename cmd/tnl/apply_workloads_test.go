package main

import (
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestApplyEnvironmentCloudSelectorsStayPublisherOwned(t *testing.T) {
	project := clientproject.Project{Config: config.TNL{Services: config.Services{"cluster": {Protocol: new("kubernetes")}}, Environments: map[string]config.Environment{"staging": {Targets: map[string]config.EnvironmentTarget{"cluster": {Discovery: &config.ServiceTarget{Type: "eks", Region: new("us-east-1"), Cluster: new("staging")}}}}}}}
	targets, err := resolve.EnvironmentTargets(t.Context(), project, "staging")
	if err != nil {
		t.Fatal(err)
	}
	if targets["cluster"].Address != nil || targets["cluster"].Tls != nil || targets["cluster"].Discovery == nil {
		t.Fatal("apply attempted local cloud discovery")
	}
}
