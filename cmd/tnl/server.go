package main

import (
	"context"

	clientserver "github.com/tnldotdev/tnl/internal/client/server"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
)

const defaultServerURL = clientserver.DefaultURL

func resolveServer(ctx context.Context, root, value string) (string, *clientstate.Database, error) {
	return clientserver.Open(ctx, root, value)
}

func clientStateRoot(root string) (string, error) {
	if root != "" {
		return root, nil
	}
	return clientstate.DefaultDir()
}
