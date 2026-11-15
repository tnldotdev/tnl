package state

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

const temporaryBlockIPKeyPurpose = "http-temporary-block"

func serviceIPKeyContext(id string) string { return "service-ip-key/" + id }

// readServiceIPKey never creates state on a read-only ingress refresh.
func (d *Database) readServiceIPKey(ctx context.Context, q *controlstatedb.Queries, service, purpose string) ([]byte, error) {
	row, err := q.ReadServiceIPKey(ctx, controlstatedb.ReadServiceIPKeyParams{ServiceID: service, Purpose: purpose})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	key, _, err := d.openSecret(row.StorageKeyID, serviceIPKeyContext(service+"/"+purpose), row.KeyCiphertext)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 || [32]byte(key) == [32]byte{} {
		clear(key)
		return nil, errors.New("invalid stored service IP key")
	}
	return key, nil
}

// ensureServiceIPKey runs only after authorization and service locking. the
// encrypted verifier survives storage-key rotation without changing IP bindings.
func (d *Database) ensureServiceIPKey(ctx context.Context, q *controlstatedb.Queries, service, purpose string) ([]byte, error) {
	key, err := d.readServiceIPKey(ctx, q, service, purpose)
	if err != nil || key != nil {
		return key, err
	}
	derived, err := d.storageKey.IPPolicyKey(d.storageKey.CurrentID(), purpose+":"+service)
	if err != nil {
		return nil, err
	}
	defer clear(derived[:])
	ciphertext, err := d.sealSecret(serviceIPKeyContext(service+"/"+purpose), derived[:])
	if err != nil {
		return nil, err
	}
	if err := q.CreateServiceIPKey(ctx, controlstatedb.CreateServiceIPKeyParams{
		ServiceID: service, Purpose: purpose, KeyCiphertext: ciphertext, StorageKeyID: d.storageKey.CurrentID(),
	}); err != nil {
		return nil, err
	}
	return d.readServiceIPKey(ctx, q, service, purpose)
}
