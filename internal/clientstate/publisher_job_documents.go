package clientstate

import (
	"context"
	"database/sql"
	"errors"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
)

const maxPublisherJobDocumentBytes = 1 << 20

// PublisherJobRegistry keeps the root-owned job snapshot sealed as one value.
func (d *Database) PublisherJobRegistry(ctx context.Context) ([]byte, bool, error) {
	stored, err := d.queries.GetPublisherJobRegistry(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	value, err := d.secrets.Open(ctx, "publisher-job-registry", stored)
	return value, true, err
}

func (d *Database) SavePublisherJobRegistry(ctx context.Context, value []byte) error {
	if len(value) == 0 || len(value) > maxPublisherJobDocumentBytes {
		return errors.New("clientstate: invalid publisher job registry")
	}
	sealed, err := d.secrets.Seal(ctx, "publisher-job-registry", value)
	if err != nil {
		return err
	}
	return d.queries.SavePublisherJobRegistry(ctx, clientstatedb.SavePublisherJobRegistryParams{
		JobsCiphertext: sealed, UpdatedAt: d.now().UTC().UnixNano(),
	})
}

// PublisherJobFileManifest stores the exact pinned-file set separately from
// the registry; both documents remain protected inside the database.
func (d *Database) PublisherJobFileManifest(ctx context.Context) ([]byte, bool, error) {
	stored, err := d.queries.GetPublisherJobFileManifest(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	value, err := d.secrets.Open(ctx, "publisher-job-file-manifest", stored)
	return value, true, err
}

func (d *Database) SavePublisherJobFileManifest(ctx context.Context, value []byte) error {
	if len(value) == 0 || len(value) > maxPublisherJobDocumentBytes {
		return errors.New("clientstate: invalid publisher job file manifest")
	}
	sealed, err := d.secrets.Seal(ctx, "publisher-job-file-manifest", value)
	if err != nil {
		return err
	}
	return d.queries.SavePublisherJobFileManifest(ctx, clientstatedb.SavePublisherJobFileManifestParams{
		ManifestCiphertext: sealed, UpdatedAt: d.now().UTC().UnixNano(),
	})
}
