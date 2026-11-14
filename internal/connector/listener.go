package connector

import (
	"context"
	"net"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// local assignments belong to this machine, identity, and immutable service.
// endpoint reachability and public port changes never select a local port.
func listenConnector(ctx context.Context, store *clientstate.Store, identity string, service controlv1.Service, override string) (net.Listener, error) {
	if override != "" {
		return store.ListenServiceAt(ctx, identity, service.Id, override)
	}
	return store.ListenService(ctx, identity, service.Id, string(service.Protocol))
}
