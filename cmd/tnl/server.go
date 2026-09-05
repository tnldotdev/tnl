package main

import (
	"context"

	"github.com/tnldotdev/tnl/internal/clientstate"
)

const defaultServerURL = "https://control.tnl.dev"

func resolveServer(ctx context.Context, root, value string) (string, *clientstate.Database, error) {
	root, err := clientStateRoot(root)
	if err != nil {
		return "", nil, err
	}
	state, err := clientstate.Open(ctx, root)
	if err != nil {
		return "", nil, err
	}
	if value != "" {
		server, err := clientstate.CanonicalServer(value)
		if err != nil {
			state.Close()
			return "", nil, err
		}
		return server, state, nil
	}
	server, found, err := state.SavedServer(ctx)
	if err != nil {
		state.Close()
		return "", nil, err
	}
	if !found {
		return defaultServerURL, state, nil
	}
	return server, state, nil
}

func clientStateRoot(root string) (string, error) {
	if root != "" {
		return root, nil
	}
	return clientstate.DefaultDir()
}
