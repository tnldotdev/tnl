package main

import (
	"context"

	"github.com/tnldotdev/tnl/internal/clientserver"
	"github.com/tnldotdev/tnl/internal/clientstate"
)

const defaultServerURL = clientserver.DefaultURL

func resolveServer(ctx context.Context, root, value string) (string, *clientstate.Database, error) {
	root, err := clientStateRoot(root)
	if err != nil {
		return "", nil, err
	}
	state, err := clientstate.Open(ctx, root)
	if err != nil {
		return "", nil, err
	}
	server, err := clientserver.Select(ctx, state, value)
	if err != nil {
		state.Close()
		return "", nil, err
	}
	return server, state, nil
}

func clientStateRoot(root string) (string, error) {
	if root != "" {
		return root, nil
	}
	return clientstate.DefaultDir()
}
