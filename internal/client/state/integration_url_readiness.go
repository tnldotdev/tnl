package state

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/client/state/clientstatedb"
)

// MarkIntegrationURLReady renews one locally ready integration URL publisher.
// only the publisher instance that marked it ready may clear the lease.
func (d *Database) MarkIntegrationURLReady(ctx context.Context, server, hostname, publisherInstanceID string) error {
	if server == "" || hostname == "" || publisherInstanceID == "" {
		return errors.New("integration URL hostname and publisher instance ID are required")
	}
	return d.queries.MarkIntegrationURLReady(ctx, clientstatedb.MarkIntegrationURLReadyParams{
		ServerOrigin: server, Hostname: hostname, PublisherInstanceID: publisherInstanceID, ExpiresAt: d.now().UTC().Add(12 * time.Second).UnixNano(),
	})
}

// SaveIntegrationURLEndpoint retains the exact endpoint reported by its publisher.
// readiness remains a separate, expiring lease.
func (d *Database) SaveIntegrationURLEndpoint(ctx context.Context, server, publicURLID, publicURL string) error {
	hostname, err := parsePublicTunnelAddress(publicURL)
	if err != nil || !validPublicURLID(publicURLID) {
		return errors.New("invalid integration URL endpoint")
	}
	return d.queries.SaveIntegrationURLEndpoint(ctx, clientstatedb.SaveIntegrationURLEndpointParams{
		ServerOrigin: server, Hostname: hostname, PublicURLID: publicURLID, PublicURL: publicURL,
	})
}

func (d *Database) IntegrationURLEndpoint(ctx context.Context, server, hostname string) (string, error) {
	origin, err := d.queries.IntegrationURLEndpoint(ctx, clientstatedb.IntegrationURLEndpointParams{ServerOrigin: server, Hostname: hostname})
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return origin, err
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
