// package clientserver selects the control URL shared by native clients.
package clientserver

import (
	"context"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
)

const DefaultURL = "https://control.tnl.dev"

func Select(ctx context.Context, state *clientstate.Database, explicit string) (string, error) {
	if explicit != "" {
		return clientstate.CanonicalServer(explicit)
	}
	server, found, err := state.SavedServer(ctx)
	if err != nil {
		return "", err
	}
	if found {
		return server, nil
	}
	return DefaultURL, nil
}
