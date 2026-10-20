package main

import (
	"context"
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/githubmetadata"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestApplyCIBindingReuseAndCloudSelectors(t *testing.T) {
	group := "production"
	repository := "example/repository"
	protocol := "kubernetes"
	project := projectConfiguration{Project: projectconfig.Project{Config: config.TNL{Publishers: map[string]config.Publisher{group: {}}, Services: config.Services{"cluster": {Publisher: &group, Protocol: &protocol, Target: &config.ServiceTarget{Type: "eks", Region: new("us-east-1"), Cluster: new("production")}}}, CI: map[string]config.CI{"test": {GitHub: config.CIGitHub{Repository: &repository, Workflow: ".github/workflows/test.yml", Ref: "refs/heads/main", Events: []string{"push"}}, Services: []string{"cluster"}}}}}}
	declaration, err := projectDeclaration(t.Context(), project, appliedTestContext(), projectconfig.SourceIdentity{})
	if err != nil {
		t.Fatal(err)
	}
	if declaration.Services["cluster"].Target != "" || declaration.Services["cluster"].TargetTls != nil || declaration.Services["cluster"].TargetDiscovery == nil {
		t.Fatal("apply attempted local cloud discovery")
	}
	original := readGitHubRepository
	t.Cleanup(func() { readGitHubRepository = original })
	calls := 0
	readGitHubRepository = func(context.Context, string) (githubmetadata.Repository, error) {
		calls++
		return githubmetadata.Repository{Repository: repository, RepositoryID: "12345", OwnerID: "6789"}, nil
	}
	if err = bindProjectCI(t.Context(), project, &declaration, controlv1.ProjectConfiguration{}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || declaration.Ci == nil || (*declaration.Ci)["test"].Github.RepositoryId != "12345" || (*declaration.Ci)["test"].MaxDurationSeconds != 3600 {
		t.Fatal("initial metadata binding missing")
	}
	saved := declaration
	readGitHubRepository = func(context.Context, string) (githubmetadata.Repository, error) {
		t.Fatal("unchanged apply required GitHub authentication")
		return githubmetadata.Repository{}, nil
	}
	if err = bindProjectCI(t.Context(), project, &declaration, saved); err != nil {
		t.Fatal(err)
	}
	cause := errors.New("private repository metadata is unavailable")
	readGitHubRepository = func(context.Context, string) (githubmetadata.Repository, error) {
		return githubmetadata.Repository{}, cause
	}
	if err = bindProjectCI(t.Context(), project, &declaration, controlv1.ProjectConfiguration{}); !errors.Is(err, cause) {
		t.Fatal("metadata setup cause was lost", err)
	}
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.CIRepositoryMetadataUnavailable {
		t.Fatal("first setup did not expose the owned GitHub metadata diagnostic", err)
	}
}
