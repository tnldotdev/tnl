package state

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/client/state/clientstatedb"
	"github.com/tnldotdev/tnl/internal/client/webhooksource"
)

// CachedWebhookPolicy returns the last policy for one server and fixed provider.
func (d *Database) CachedWebhookPolicy(ctx context.Context, server, provider string) (webhooksource.CacheEntry, error) {
	if !webhooksource.Valid(provider) {
		return webhooksource.CacheEntry{}, errors.New("invalid webhook provider")
	}
	store, err := d.Server(ctx, server)
	if err != nil {
		return webhooksource.CacheEntry{}, err
	}
	row, err := d.queries.GetWebhookCatalog(ctx, clientstatedb.GetWebhookCatalogParams{ServerOrigin: store.controlEndpoint, Provider: provider})
	if err != nil {
		return webhooksource.CacheEntry{}, err
	}
	return webhooksource.CacheEntry{JSON: []byte(row.SourceJson), ETag: row.Etag,
		CheckedAt: time.Unix(0, row.CheckedAt), ExpiresAt: time.Unix(0, row.ExpiresAt)}, nil
}

// SaveWebhookPolicy updates the bounded client-state copy of a validated catalog response.
func (d *Database) SaveWebhookPolicy(ctx context.Context, server, provider string, entry webhooksource.CacheEntry) error {
	if !webhooksource.Valid(provider) || len(entry.JSON) == 0 || len(entry.JSON) > 16384 || len(entry.ETag) > 128 ||
		entry.CheckedAt.IsZero() || !entry.ExpiresAt.After(entry.CheckedAt) {
		return errors.New("invalid cached webhook policy")
	}
	store, err := d.Server(ctx, server)
	if err != nil {
		return err
	}
	return d.queries.PutWebhookCatalog(ctx, clientstatedb.PutWebhookCatalogParams{
		ServerOrigin: store.controlEndpoint, Provider: provider, SourceJson: string(entry.JSON), Etag: entry.ETag,
		CheckedAt: entry.CheckedAt.UnixNano(), ExpiresAt: entry.ExpiresAt.UnixNano(),
	})
}
