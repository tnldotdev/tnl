package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func localServiceHTTPContext(service string) string { return "local-service-http/" + service }

// local realization can precede apply. retain its request policy with the exact
// worktree binding rather than reading another worktree or a desired declaration.
func (d *Database) saveLocalServiceHTTP(ctx context.Context, tx pgx.Tx, service string, value *config.HTTPService) error {
	var policy *config.HTTPService
	if value != nil && (value.Access != nil || value.Limits != nil) {
		policy = &config.HTTPService{Access: value.Access, Limits: value.Limits}
	}
	if err := config.ValidateServiceHTTP(policy); err != nil {
		return errors.Join(ErrProjectConfigurationInvalid, err)
	}
	q := controlstatedb.New(tx)
	row, err := q.GetLocalServiceHTTPConfiguration(ctx, text(service))
	if err != nil {
		return err
	}
	previous, err := d.openLocalServiceHTTP(service, row.HttpStorageKeyID.String, row.HttpConfigurationCiphertext)
	if err != nil {
		return err
	}
	if reflect.DeepEqual(previous, policy) {
		return nil
	}
	var sealed []byte
	key := ""
	if policy != nil {
		data, err := json.Marshal(policy)
		if err != nil {
			return err
		}
		sealed, err = d.storageKey.Seal(localServiceHTTPContext(service), data)
		if err != nil {
			return err
		}
		key = d.storageKey.CurrentID()
	}
	updated, err := q.SetLocalServiceHTTPConfiguration(ctx, controlstatedb.SetLocalServiceHTTPConfigurationParams{ServiceID: text(service), Ciphertext: sealed, StorageKeyID: nullableText(key)})
	if err != nil {
		return err
	}
	if updated != 1 {
		return ErrProjectConfigurationStale
	}
	_, err = tx.Exec(ctx, `SELECT control.touch_visitor_policy('service',$1)`, service)
	return err
}

func (d *Database) openLocalServiceHTTP(service, key string, sealed []byte) (*config.HTTPService, error) {
	if len(sealed) == 0 {
		if key != "" {
			return nil, ErrServiceAccess
		}
		return nil, nil
	}
	data, _, err := d.storageKey.Open(key, localServiceHTTPContext(service), sealed)
	if err != nil {
		return nil, err
	}
	var policy *config.HTTPService
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return nil, errors.Join(ErrServiceAccess, err)
	}
	if policy == nil || decoder.Decode(new(any)) != io.EOF || config.ValidateRemoteHTTP(policy) != nil {
		return nil, ErrServiceAccess
	}
	return policy, nil
}
