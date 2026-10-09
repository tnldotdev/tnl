package clientstate

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
	"github.com/tnldotdev/tnl/internal/webhookips"
)

// CachedWebhookPolicy returns the last policy for a fixed provider enum value.
func (d *Database) CachedWebhookPolicy(ctx context.Context, provider string) (webhookips.CacheEntry, error) {
	if !webhookips.Valid(provider) {
		return webhookips.CacheEntry{}, errors.New("invalid webhook provider")
	}
	row, err := d.queries.GetWebhookCatalog(ctx, provider)
	if err != nil {
		return webhookips.CacheEntry{}, err
	}
	return webhookips.CacheEntry{JSON: []byte(row.SourceJson), ETag: row.Etag,
		CheckedAt: time.Unix(0, row.CheckedAt), ExpiresAt: time.Unix(0, row.ExpiresAt)}, nil
}

// SaveWebhookPolicy updates the bounded client-state copy of a validated catalog response.
func (d *Database) SaveWebhookPolicy(ctx context.Context, provider string, entry webhookips.CacheEntry) error {
	if !webhookips.Valid(provider) || len(entry.JSON) == 0 || len(entry.JSON) > 16384 || len(entry.ETag) > 128 ||
		entry.CheckedAt.IsZero() || !entry.ExpiresAt.After(entry.CheckedAt) {
		return errors.New("invalid cached webhook policy")
	}
	return d.queries.PutWebhookCatalog(ctx, clientstatedb.PutWebhookCatalogParams{
		Provider: provider, SourceJson: string(entry.JSON), Etag: entry.ETag,
		CheckedAt: entry.CheckedAt.UnixNano(), ExpiresAt: entry.ExpiresAt.UnixNano(),
	})
}
