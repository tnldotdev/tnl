package state

import (
	"context"
	"fmt"

	"github.com/tnldotdev/tnl/internal/client/state/clientstatedb"
)

// KnownProjectServices returns IDs previously published by this
// project/server, including services whose local tunnels have stopped.
// these IDs select a fresh signed read; they do not prove current authority.
func (d *Database) KnownProjectServices(ctx context.Context, project, server string) ([]string, error) {
	project, err := runtimeProject(project)
	if err != nil {
		return nil, err
	}
	canonical, err := CanonicalServer(server)
	if err != nil {
		return nil, err
	}
	ids, err := d.queries.ListKnownProjectServices(ctx, clientstatedb.ListKnownProjectServicesParams{
		ProjectRoot: project, ServerOrigin: canonical,
	})
	if err != nil {
		return nil, fmt.Errorf("clientstate: read known project services: %w", err)
	}
	if ids == nil {
		ids = []string{}
	}
	return ids, nil
}
