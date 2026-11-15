package state

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/client/state/clientstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// MarkIntegrationURLReady renews one locally ready integration service run.
// only the publisher instance that marked it ready may clear the lease.
func (d *Database) MarkIntegrationURLReady(ctx context.Context, server, hostname, publisherInstanceID, serviceID string, runNumber uint64) error {
	number, err := databaseVersion(runNumber)
	if err != nil || number == 0 || server == "" || hostname == "" || publisherInstanceID == "" || !opaqueid.Valid(serviceID, opaqueid.ServicePrefix) {
		return errors.New("integration service hostname, publisher instance, service ID and run number are required")
	}
	return d.queries.MarkIntegrationURLReady(ctx, clientstatedb.MarkIntegrationURLReadyParams{
		ServerOrigin: server, Hostname: hostname, PublisherInstanceID: publisherInstanceID,
		ServiceID: serviceID, RunNumber: number, ExpiresAt: d.now().UTC().Add(12 * time.Second).UnixNano(),
	})
}

func (d *Database) IntegrationURLReady(ctx context.Context, server, hostname string) (bool, error) {
	found, err := d.queries.IntegrationURLReady(ctx, clientstatedb.IntegrationURLReadyParams{
		ServerOrigin: server, Hostname: hostname, Now: d.now().UTC().UnixNano(),
	})
	return found == 1, err
}

func (d *Database) ClearIntegrationURLReady(ctx context.Context, server, hostname, publisherInstanceID string) error {
	return d.queries.ClearIntegrationURLReady(ctx, clientstatedb.ClearIntegrationURLReadyParams{ServerOrigin: server, Hostname: hostname, PublisherInstanceID: publisherInstanceID})
}
