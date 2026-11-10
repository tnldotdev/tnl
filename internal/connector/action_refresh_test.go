package connector

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/project/workloadmanifest"
	"github.com/tnldotdev/tnl/internal/config"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
)

func TestConnectionActionRefreshRequiresSelectedGitHubPolicy(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*OwnerStartOptions, *projectConfiguration, *connectorruntime.StartRequest)
	}{
		{"selected policy", nil},
		{"other audience", func(_ *OwnerStartOptions, _ *projectConfiguration, r *connectorruntime.StartRequest) {
			r.GitHubActionsRefresh.Audience = "https://other.example.test"
		}},
		{"initial assertion required", func(_ *OwnerStartOptions, _ *projectConfiguration, r *connectorruntime.StartRequest) {
			r.Assertion = ""
		}},
		{"workload required", func(_ *OwnerStartOptions, _ *projectConfiguration, r *connectorruntime.StartRequest) {
			r.Context.Workload = ""
		}},
		{"one refresh source", func(_ *OwnerStartOptions, _ *projectConfiguration, r *connectorruntime.StartRequest) {
			r.Refresh = &workloadmanifest.Acquisition{Method: "token-file", TokenFile: "/run/current.jwt"}
		}},
		{"SDK parent is not Action ownership", func(o *OwnerStartOptions, _ *projectConfiguration, _ *connectorruntime.StartRequest) {
			o.ParentPID = 123
		}},
		{"SDK registry is not Action ownership", func(o *OwnerStartOptions, _ *projectConfiguration, _ *connectorruntime.StartRequest) {
			o.SDKRegistry = "/run/sdk"
		}},
		{"other provider", func(_ *OwnerStartOptions, p *projectConfiguration, _ *connectorruntime.StartRequest) {
			p.Config.Workloads["job"] = config.Workload{Fly: &config.WorkloadFly{App: "example"}}
		}},
		{"selected file is not runtime acquisition", func(_ *OwnerStartOptions, p *projectConfiguration, _ *connectorruntime.StartRequest) {
			policy := p.Config.Workloads["job"]
			policy.Token = &config.WorkloadToken{File: new("current.jwt")}
			p.Config.Workloads["job"] = policy
		}},
		{"insecure source", func(_ *OwnerStartOptions, _ *projectConfiguration, r *connectorruntime.StartRequest) {
			r.GitHubActionsRefresh.RequestURL = "http://runtime.example.test/token"
		}},
		{"missing source credential", func(_ *OwnerStartOptions, _ *projectConfiguration, r *connectorruntime.StartRequest) {
			r.GitHubActionsRefresh.RequestToken = ""
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := OwnerStartOptions{ContextOptions: ContextOptions{Workload: "job"}}
			project := projectConfiguration{}
			project.Config.Workloads = map[string]config.Workload{"job": {GitHub: &config.WorkloadGitHub{Workflow: ".github/workflows/job.yml"}}}
			request := connectorruntime.StartRequest{Schema: 1, Context: connectorruntime.Context{Workload: "job", Audience: "https://control.example.test"}, Assertion: "initial.private.jwt", GitHubActionsRefresh: &connectorruntime.GitHubActionsRefresh{Audience: "https://control.example.test", RequestURL: "https://runtime.example.test/token", RequestToken: "private-runtime-bearer"}}
			if test.change != nil {
				test.change(&options, &project, &request)
			}
			err := validateGitHubActionsRefresh(options, project, request)
			if test.change == nil && err != nil || test.change != nil && !errors.Is(err, connectorruntime.ErrInvalid) {
				t.Fatal("Action refresh did not retain its selected source boundary", err)
			}
		})
	}
}

func TestConnectionActionRefreshPinsManifestSelection(t *testing.T) {
	manifest := workloadmanifest.Manifest{Schema: 1, Server: "https://control.example.test", Team: "team", ProjectKey: "project", ProjectLabel: "app", SourceFingerprint: strings.Repeat("a", 64), Services: map[string]string{"db": "postgres"}, Workloads: map[string]workloadmanifest.Workload{"job": {Provider: "github", Grants: config.ServiceVisitGrants("db"), MaxDurationSeconds: 3600, Acquisition: workloadmanifest.Acquisition{Method: "github-actions", Audience: "https://control.example.test"}}}}
	file := filepath.Join(t.TempDir(), "workloads.json")
	write := func() {
		t.Helper()
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	options := OwnerStartOptions{ContextOptions: ContextOptions{Directory: filepath.Dir(file), Manifest: file, Workload: "job"}}
	project, scope, err := connectionProject(t.Context(), options.ContextOptions)
	if err != nil {
		t.Fatal(err)
	}
	request := connectorruntime.StartRequest{Schema: 1, Context: scope, Assertion: "initial.private.jwt", GitHubActionsRefresh: &connectorruntime.GitHubActionsRefresh{Audience: scope.Audience, RequestURL: "https://runtime.example.test/token", RequestToken: "private-runtime-bearer"}}
	if err := validateGitHubActionsRefresh(options, project, request); err != nil {
		t.Fatal("selected GitHub manifest rejected", err)
	}
	policy := manifest.Workloads["job"]
	policy.MaxDurationSeconds = 1800
	manifest.Workloads["job"] = policy
	write()
	if err := validateGitHubActionsRefresh(options, project, request); !errors.Is(err, connectorruntime.ErrInvalid) {
		t.Fatal("refresh silently switched to a changed manifest", err)
	}
	policy.Provider, policy.Acquisition = "vercel", workloadmanifest.Acquisition{Method: "vercel-oidc"}
	manifest.Workloads["job"] = policy
	write()
	project, request.Context, err = connectionProject(t.Context(), options.ContextOptions)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateGitHubActionsRefresh(options, project, request); !errors.Is(err, connectorruntime.ErrInvalid) {
		t.Fatal("GitHub source accepted a non-GitHub manifest", err)
	}
}
