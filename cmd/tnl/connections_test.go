package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/connectionruntime"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
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
	configuration := `{"version":1,"tnl":{"server":"https://control.example","team":"acme","publishers":{"production":{}},"services":{"database":{"protocol":"postgres","publisher":"production","target":{"type":"address","address":"unused.invalid:5432"}},"unrequested":{"protocol":"mysql","publisher":"production","target":{"type":"address","address":"unused.invalid:3306"}},"web":{"public_url":{},"target":{"type":"address","address":"http://unused.invalid:3000"}},"managed":{"publisher":"production","public_url":{},"target":{"type":"address","address":"http://unused.invalid:3001"}}},"ci":{"migrate":{"github":{"workflow":".github/workflows/migrate.yml","ref":"refs/heads/main","events":["push"]},"services":["database"]}}}}`
	if err := os.WriteFile(filepath.Join(root, "tnl.json"), []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	options := connectionsContextOptions{Directory: root, StateDir: filepath.Join(root, "must-not-open-state"), Service: []string{"database"}}
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
	if _, _, err := connectionProject(t.Context(), all); !errors.Is(err, connectionruntime.ErrInvalid) {
		t.Fatal("native context selected a public URL declaration", err)
	}
	options.CI = "migrate"
	if _, _, err := connectionProject(t.Context(), options); !errors.Is(err, connectionruntime.ErrTeam) {
		t.Fatal("unbound team name did not fail closed", err)
	}
	team, _ := opaqueid.New(opaqueid.TeamPrefix)
	if err := connectionruntime.WriteBinding(root, connectionruntime.Binding{Schema: 1, Server: local.Server, Team: "acme", TeamID: team, ProjectKey: local.ProjectKey, SourceID: local.SourceID}); err != nil {
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
	if _, _, err := connectionProject(t.Context(), options); !errors.Is(err, connectionruntime.ErrTeam) {
		t.Fatal("binding crossed project sources", err)
	}
}

func TestConnectionKubernetesUsesSavedAuthHint(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	team, _ := opaqueid.New(opaqueid.TeamPrefix)
	service, _ := opaqueid.New(opaqueid.PrivateServicePrefix)
	localCluster, localRegion := "unapplied-local", "us-west-2"
	b := nativeConnectionBackend{directory: directory, executable: "/absolute/tnl", scope: connectionruntime.Context{CI: "test", Server: "https://control.example", TeamID: team, SourceID: "source", ProjectLabel: "shop"}}
	b.project.Config.Services = map[string]config.Service{"cluster": {Target: &config.ServiceTarget{Type: "eks", Cluster: &localCluster, Region: &localRegion}}}
	p := preparedConnection{service: controlv1.PrivateService{Id: service, ManagedTls: &controlv1.ManagedServiceTLS{Hostname: "cluster.example"}, KubernetesAuth: &controlv1.KubernetesAuth{Provider: controlv1.KubernetesEKS, Cluster: "applied-cluster", Region: "us-east-1"}}, connection: connectionruntime.Connection{Host: "127.0.0.1", Port: 25443, URL: "https://cluster.example:25443"}}
	if err := b.prepareKube(t.Context(), "cluster", &p); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.sessionKubePlan.CleanupSession(t.Context(), b.sessionKubeResult) })
	if p.kubeSource.EKS == nil || p.kubeSource.EKS.Cluster != "applied-cluster" || p.kubeSource.EKS.Region != "us-east-1" {
		t.Fatal("native credentials used unapplied local selectors")
	}
}

func TestConnectionMachineErrorsAreOwnedAndSafeWithoutOutputFlag(t *testing.T) {
	var output bytes.Buffer
	err := run(t.Context(), []string{"runtime", "connections", "status", "--handle", "/missing/secret-handle"}, &output, &output)
	var machine *machineCommandError
	if !errors.As(err, &machine) {
		t.Fatal("machine command returned a human error", err)
	}
	writeCommandError(&output, err)
	var diagnostic map[string]any
	if json.Unmarshal(output.Bytes(), &diagnostic) != nil || diagnostic["reason"] != string(failure.ConnectionHandleInvalid) || bytes.Contains(output.Bytes(), []byte("secret-handle")) {
		t.Fatal("unsafe machine diagnostic", output.String())
	}
	if connectionReason(syscall.EADDRINUSE) != failure.ConnectionPortInUse {
		t.Fatal("port collision lost its boundary")
	}
}
