package resolve

import (
	"context"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/meta"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
)

func IntegrationOrigin(ctx context.Context, state *clientstate.Database, project clientproject.Project, server, namespace, purpose string) (meta.IntegrationOrigin, error) {
	salt, err := state.WorktreeHashSalt(ctx)
	if err != nil {
		return meta.IntegrationOrigin{}, err
	}
	proposed := clientproject.SharedProjectLabel(purpose, project.Worktree, project.Root, salt) + "." + namespace
	hostname, err := state.IntegrationURLHostname(ctx, server, clientproject.SharedProjectIdentity(project.Worktree, project.Root), namespace, purpose, proposed)
	if err != nil {
		return meta.IntegrationOrigin{}, err
	}
	return meta.IntegrationOrigin{Hostname: hostname, URL: "https://" + hostname}, nil
}
