package clientstate

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
)

// MarkIntegrationURLReady renews one locally ready integration URL publisher.
// only the publisher's owner may remove it on a graceful stop.
func (d *Database) MarkIntegrationURLReady(ctx context.Context, server, hostname, owner string) error {
	if server == "" || hostname == "" || owner == "" {
		return errors.New("integration URL hostname and publisher owner are required")
	}
	return d.queries.MarkIntegrationURLReady(ctx, clientstatedb.MarkIntegrationURLReadyParams{
		ServerOrigin: server, Hostname: hostname, Owner: owner, ExpiresAt: d.now().UTC().Add(12 * time.Second).UnixNano(),
	})
}

func (d *Database) IntegrationURLReady(ctx context.Context, server, hostname string) (bool, error) {
	found, err := d.queries.IntegrationURLReady(ctx, clientstatedb.IntegrationURLReadyParams{
		ServerOrigin: server, Hostname: hostname, Now: d.now().UTC().UnixNano(),
	})
	return found == 1, err
}

func (d *Database) ClearIntegrationURLReady(ctx context.Context, server, hostname, owner string) error {
	return d.queries.ClearIntegrationURLReady(ctx, clientstatedb.ClearIntegrationURLReadyParams{ServerOrigin: server, Hostname: hostname, Owner: owner})
}
