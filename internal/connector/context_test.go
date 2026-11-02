package connector

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestConnectionContextAppliedTeamNameWithoutHumanState(t *testing.T) {
	t.Setenv("TNL_SERVER", "")
	t.Setenv("TNL_CONFIG", "")
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "--quiet", root}, {"-C", root, "remote", "add", "origin", "https://github.com/fixture/shop.git"}} {
		if output, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("fixture git: %v %s", err, output)
		}
	}
	configuration := `{"version":1,"tnl":{"server":"https://control.example","team":"acme","publisher_groups":{"production":{}},"services":{"database":{"protocol":"postgres","publisher_group":"production","target":{"type":"address","address":"unused.invalid:5432"}},"unrequested":{"protocol":"mysql","publisher_group":"production","target":{"type":"address","address":"unused.invalid:3306"}},"web":{"public_url":{},"target":{"type":"address","address":"http://unused.invalid:3000"}},"managed":{"publisher_group":"production","target":{"type":"address","address":"http://unused.invalid:3001"},"http":{}}},"workloads":{"migrate":{"provider":"github","github":{"workflow":".github/workflows/migrate.yml","ref":"refs/heads/main","events":["push"]},"services":["database"]}}}}`
	if err := os.WriteFile(filepath.Join(root, "tnl.json"), []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	options := ContextOptions{Directory: root, StateDir: filepath.Join(root, "must-not-open-state"), Service: []string{"database"}}
	_, local, err := connectionProject(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(local.Services, []string{"database"}) {
		t.Fatal("requested preparation included unrelated services", local.Services)
	}
	all := options
	all.Service = nil
	_, implicit, err := connectionProject(t.Context(), all)
	if err != nil || !slices.Equal(implicit.Services, []string{"database", "managed", "unrequested"}) {
		t.Fatal("context confused managed policy with public URL declarations", implicit.Services, err)
	}
	all.Service = []string{"web"}
	if _, _, err := connectionProject(t.Context(), all); !errors.Is(err, connectorruntime.ErrInvalid) {
		t.Fatal("native context selected a public URL declaration", err)
	}
	options.Workload = "migrate"
	if _, scope, err := connectionProject(t.Context(), options); err != nil || scope.TeamID != "acme" {
		t.Fatal("team selector was not retained for saved-policy exchange", err)
	}
	team, _ := opaqueid.New(opaqueid.TeamPrefix)
	if err := connectorruntime.WriteBinding(root, connectorruntime.Binding{Schema: 1, Server: local.Server, Team: "acme", TeamID: team, ProjectKey: local.ProjectKey, SourceID: local.SourceID}); err != nil {
		t.Fatal(err)
	}
	_, scope, err := connectionProject(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	if scope.TeamID != team || scope.Audience != "https://control.example" || scope.ProjectKey != local.ProjectKey {
		t.Fatal("context selected another applied scope")
	}
	if _, err := os.Stat(options.StateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("context opened human state", err)
	}
	if output, err := exec.CommandContext(t.Context(), "git", "-C", root, "remote", "set-url", "origin", "https://github.com/fixture/replaced.git").CombinedOutput(); err != nil {
		t.Fatalf("replace origin: %v %s", err, output)
	}
	if _, scope, err := connectionProject(t.Context(), options); err != nil || scope.TeamID != "acme" {
		t.Fatal("binding crossed project sources", err)
	}
}

func TestConnectionKubernetesUsesSavedAuthHint(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	team, _ := opaqueid.New(opaqueid.TeamPrefix)
	service, _ := opaqueid.New(opaqueid.ServicePrefix)
	localCluster, localRegion := "unapplied-local", "us-west-2"
	b := connectorConnectionBackend{directory: directory, executable: "/absolute/tnl", connectorConnectionSession: connectorConnectionSession{teamID: team}, scope: connectorruntime.Context{Workload: "test", Server: "https://control.example", TeamID: team, SourceID: "source", ProjectLabel: "shop"}}
	b.project.Config.Services = map[string]config.Service{"cluster": {Target: &config.ServiceTarget{Type: "eks", Cluster: &localCluster, Region: &localRegion}}}
	p := preparedConnection{service: controlv1.Service{Id: service, Endpoint: &controlv1.ServiceEndpoint{Hostname: "cluster.example"}, KubernetesAuth: &controlv1.KubernetesAuth{Provider: controlv1.KubernetesEKS, Cluster: "applied-cluster", Region: "us-east-1"}}, connection: connectorruntime.Connection{Host: "127.0.0.1", Port: 25443, URL: "https://cluster.example:25443"}}
	if err := b.prepareKube(t.Context(), "cluster", &p); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.sessionKubePlan.CleanupSession(t.Context(), b.sessionKubeResult) })
	if p.kubeSource.EKS == nil || p.kubeSource.EKS.Cluster != "applied-cluster" || p.kubeSource.EKS.Region != "us-east-1" {
		t.Fatal("native credentials used unapplied local selectors")
	}
}
