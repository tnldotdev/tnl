package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	"github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/config"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestApplyWorkloadCloudSelectors(t *testing.T) {
	deployment := "production"
	repository := "example/repository"
	protocol := "kubernetes"
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{Deployment: deployment, Services: config.Services{"cluster": {Protocol: &protocol, Target: &config.ServiceTarget{Type: "eks", Region: new("us-east-1"), Cluster: new("production")}}}, Workloads: map[string]config.Workload{"test": {GitHub: &config.WorkloadGitHub{Repository: &repository, Workflow: ".github/workflows/test.yml", Branch: new("main")}, Services: []string{"cluster"}}}}}}
	declaration, err := resolve.Declaration(t.Context(), project.Project, team.Context{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if declaration.Services["cluster"].Target != "" || declaration.Services["cluster"].TargetTls != nil || declaration.Services["cluster"].TargetDiscovery == nil {
		t.Fatal("apply attempted local cloud discovery")
	}
}

func TestApplyDryRunDoesNotWriteWorkloadBinding(t *testing.T) {
	const origin = "https://example.test/studio/app.git"
	root := t.TempDir()
	for _, args := range [][]string{{"init", "--quiet"}, {"remote", "add", "origin", origin}} {
		cmd := exec.CommandContext(t.Context(), "git", args...)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fixture Git setup: %v %s", err, out)
		}
	}
	path := filepath.Join(root, "tnl.json")
	if err := os.WriteFile(path, []byte(`{
		"version": 1, "tnl": {
			"services": {"web": {}},
			"deployments": {"production": {"targets": {"web": {"address": "http://web.example.test"}}}},
			"workloads": {
				"build": {"deployment": "production", "services": ["web"], "oidc": {
					"issuer": "https://issuer.example.test", "jwks_url": "https://issuer.example.test/keys",
					"claims": {"sub": "studio"}
				}}
			}
		}
	}`), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := (naming.GitProjectSource{GitOrigin: origin, ConfigurationPath: "tnl.json"}).Identity()
	if err != nil {
		t.Fatal(err)
	}
	token, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TNL_ACCESS_TOKEN", token.String())
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var body any
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/discovery":
			body = controlv1.ControlDiscovery{
				ManagedUrlMode: controlv1.Simple,
				Authentication: controlv1.AuthenticationFacts{Methods: []controlv1.AuthenticationFactsMethods{controlv1.Oidc},
					Oidc: &controlv1.OIDCAuthenticationFacts{Issuer: "https://issuer.example.test", LoginFlow: controlv1.DeviceCode}},
			}
		case "GET /v1/identity":
			body = authorityv1.IdentityContext{PersonalTeamId: statusTestTeamOne, Memberships: []authorityv1.Membership{{TeamId: statusTestTeamOne}}}
		case "GET /v1/teams/" + statusTestTeamOne:
			body = authorityv1.Team{Id: statusTestTeamOne, DisplayName: "studio", DefaultDomainId: "domain"}
		case "GET /v1/teams/" + statusTestTeamOne + "/domains":
			body = authorityv1.DomainPage{}
		case "GET /v1/projects/" + source.Key + "/configuration":
			body = controlv1.AppliedProjectConfiguration{SourceFingerprint: source.Fingerprint, Revision: 1}
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := json.NewEncoder(w).Encode(body); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	original := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	defer func() { http.DefaultTransport = original }()
	var output bytes.Buffer
	err = run(t.Context(), []string{"--config", path, "apply", "--deployment", "production", "--dry-run", "--output", "json",
		"--server", server.URL, "--state-dir", filepath.Join(root, "state")}, &output, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var preview applyDiff
	if err := json.Unmarshal(output.Bytes(), &preview); err != nil || preview.Base != 1 ||
		!slices.ContainsFunc(preview.Changes, func(change applyChange) bool {
			return change.Resource == "workload" && change.Name == "build"
		}) {
		t.Fatalf("preview omitted workload: %s (%v)", output.String(), err)
	}
	if _, err := os.Stat(filepath.Join(root, connectorruntime.BindingPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preview wrote the workload binding: %v", err)
	}
}
