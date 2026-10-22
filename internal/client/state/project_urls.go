package clientstate

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/tnldotdev/tnl/internal/client/state/clientstatedb"
)

// KnownProjectPublicURLs returns bounded IDs previously published by this
// project/server, including saved URLs whose local tunnels have stopped.
// these IDs select a fresh server read; they do not claim a URL is still saved.
func (d *Database) KnownProjectPublicURLs(ctx context.Context, project, server string) ([]string, error) {
	if project == "" || !filepath.IsAbs(project) {
		return nil, errors.New("clientstate: absolute project root is required")
	}
	canonical, err := CanonicalServer(server)
	if err != nil {
		return nil, err
	}
	ids, err := d.queries.ListKnownProjectURLs(ctx, clientstatedb.ListKnownProjectURLsParams{
		ProjectRoot: filepath.Clean(project), ServerOrigin: canonical,
	})
	if err != nil {
		return nil, fmt.Errorf("clientstate: read known project public URLs: %w", err)
	}
	if ids == nil {
		ids = []string{}
	}
	return ids, nil
}
