package main

import (
	"context"
	"io"

	"github.com/tnldotdev/tnl/internal/clientstate"
)

const defaultServerURL = "https://control.tnl.dev"

func diagnosticOutput(outputs []io.Writer) io.Writer {
	if len(outputs) != 0 && outputs[0] != nil {
		return outputs[0]
	}
	return io.Discard
}

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
