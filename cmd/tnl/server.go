package main

import (
	"context"
	"os"

	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	clientserver "github.com/tnldotdev/tnl/internal/client/server"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
)

const defaultServerURL = clientserver.DefaultURL

// keep the hosted server in a suggested command only if omitting it changes
// server selection or would make the command reject an environment credential.
func suggestedServer(ctx context.Context, server string, project *string, token, root string, db *clientstate.Database) string {
	if server == "" {
		return ""
	}
	origin, err := clientstate.CanonicalServer(server)
	if err != nil || origin != defaultServerURL {
		return server
	}
	implicit, _, err := resolve.Server(os.Getenv("TNL_SERVER"), project, token)
	if err == nil && (implicit != "" || db != nil) {
		implicit, err = clientserver.Select(ctx, db, implicit)
	} else if err == nil {
		root, err = clientStateRoot(root)
		if err == nil {
			var found bool
			implicit, found, err = clientstate.SavedServerAt(ctx, root)
			if !found && err == nil {
				implicit = defaultServerURL
			}
		}
	}
	if err == nil && implicit == origin {
		return ""
	}
	return origin
}

func configArgs(noConfig bool, path string) string {
	if noConfig {
		return "--no-config "
	}
	if path != "" {
		return "--config=" + shellWord(path) + " "
	}
	return ""
}

func resolveServer(ctx context.Context, root, value string) (string, *clientstate.Database, error) {
	return clientserver.Open(ctx, root, value)
}

func clientStateRoot(root string) (string, error) {
	if root != "" {
		return root, nil
	}
	return clientstate.DefaultDir()
}
