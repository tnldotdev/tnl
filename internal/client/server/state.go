package clientserver

import (
	"context"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
)

// Open resolves the selected server and returns its owned client database.
func Open(ctx context.Context, root, value string) (string, *clientstate.Database, error) {
	if root == "" {
		var err error
		root, err = clientstate.DefaultDir()
		if err != nil {
			return "", nil, err
		}
	}
	database, err := clientstate.Open(ctx, root)
	if err != nil {
		return "", nil, err
	}
	server, err := Select(ctx, database, value)
	if err != nil {
		_ = database.Close()
		return "", nil, err
	}
	return server, database, nil
}
