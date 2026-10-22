package resolve

import (
	"context"

	projectconfig "github.com/tnldotdev/tnl/internal/client/project"
	projectmeta "github.com/tnldotdev/tnl/internal/client/project/meta"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
)

func IntegrationOrigin(ctx context.Context, state *clientstate.Database, project projectconfig.Project, server, namespace, purpose string) (projectmeta.IntegrationOrigin, error) {
	salt, err := state.WorktreeHashSalt(ctx)
	if err != nil {
		return projectmeta.IntegrationOrigin{}, err
	}
	proposed := projectconfig.SharedProjectLabel(purpose, project.Worktree, project.Root, salt) + "." + namespace
	hostname, err := state.IntegrationURLHostname(ctx, server, projectconfig.SharedProjectIdentity(project.Worktree, project.Root), namespace, purpose, proposed)
	if err != nil {
		return projectmeta.IntegrationOrigin{}, err
	}
	return projectmeta.IntegrationOrigin{Hostname: hostname, URL: "https://" + hostname}, nil
}
