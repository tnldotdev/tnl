package state

import (
	"context"
	"io"

	"github.com/tnldotdev/tnl/internal/naming"
)

// PublisherEnrollmentFiles stores one encrypted SDK enrollment record. the slot
// is independent of the server profile so reopening can verify the saved origin
// before selecting a control client.
type PublisherEnrollmentFiles struct {
	dir       *PrivateDirectory
	base      string
	protector scopedProtector
}

func (d *Database) PublisherEnrollmentFiles(instance string) (*PublisherEnrollmentFiles, error) {
	if !naming.ValidServiceName(instance) {
		return nil, ErrPublisherStateConflict
	}
	// use the existing durable state root. atomic record replacement also syncs
	// this directory before the caller can redeem enrollment over the network.
	dir, err := OpenPrivateDirectory(d.Root())
	if err != nil {
		return nil, err
	}
	base := "sdk-publisher-" + instance
	return &PublisherEnrollmentFiles{
		dir: dir, base: base,
		protector: scopedProtector{protector: d.secrets, scope: base},
	}, nil
}

const publisherEnrollmentSealedOverhead = 128

func (f *PublisherEnrollmentFiles) Read(ctx context.Context, name string, limit int64) ([]byte, bool, error) {
	if name != "identity.json" || limit <= 0 || limit > 8192 {
		return nil, false, ErrPublisherStateConflict
	}
	if err := context.Cause(ctx); err != nil {
		return nil, false, err
	}
	sealed, found, err := f.dir.Read(f.base+".sealed", limit+publisherEnrollmentSealedOverhead)
	if err != nil || !found {
		return nil, false, err
	}
	value, err := f.protector.Open(ctx, name, sealed)
	if err != nil || int64(len(value)) > limit {
		clear(value)
		if err == nil {
			err = ErrPublisherStateConflict
		}
		return nil, false, err
	}
	return value, true, nil
}

func (f *PublisherEnrollmentFiles) Write(ctx context.Context, name string, value []byte) error {
	if name != "identity.json" || len(value) == 0 || len(value) > 8192 {
		return ErrPublisherStateConflict
	}
	sealed, err := f.protector.Seal(ctx, name, value)
	if err != nil {
		return err
	}
	return f.dir.Write(f.base+".sealed", sealed)
}

func (f *PublisherEnrollmentFiles) Lock(ctx context.Context, name string) (io.Closer, error) {
	if name != "enrollment-owner" {
		return nil, ErrPublisherStateConflict
	}
	return f.dir.Lock(ctx, f.base+".lock")
}
