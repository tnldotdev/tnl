package clientstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
)

// PublisherSigningIdentity leaves key algorithms and wire encoding to the
// publisher. private values are opaque to storage and always authenticated.
type PublisherSigningIdentity struct {
	ID           string `json:"identity_id"`
	PublicValue  []byte `json:"public_value"`
	PrivateValue []byte `json:"-"`
}

func identityContext(scope, id string, public []byte) string {
	value, _ := json.Marshal([]any{"publisher-signing-identity", scope, id, public})
	return string(value)
}

func (s *Store) PublisherSigningIdentity(ctx context.Context, scope string) (PublisherSigningIdentity, bool, error) {
	if !validOpaqueValue(scope, 1024) {
		return PublisherSigningIdentity{}, false, errors.New("clientstate: invalid publisher identity scope")
	}
	row, err := s.database.queries.GetPublisherSigningIdentity(ctx, clientstatedb.GetPublisherSigningIdentityParams{ServerOrigin: s.controlEndpoint, Scope: scope})
	if errors.Is(err, sql.ErrNoRows) {
		return PublisherSigningIdentity{}, false, nil
	}
	if err != nil {
		return PublisherSigningIdentity{}, false, err
	}
	private, err := s.secrets.Open(ctx, identityContext(scope, row.IdentityID, row.PublicValue), row.StoredPrivate)
	if err != nil {
		return PublisherSigningIdentity{}, true, err
	}
	return PublisherSigningIdentity{ID: row.IdentityID, PublicValue: row.PublicValue, PrivateValue: private}, true, nil
}

func (s *Store) SavePublisherSigningIdentity(ctx context.Context, scope string, identity PublisherSigningIdentity) error {
	if !validOpaqueValue(scope, 1024) || !validOpaqueValue(identity.ID, 256) || len(identity.PublicValue) == 0 || len(identity.PublicValue) > 65536 || len(identity.PrivateValue) == 0 || len(identity.PrivateValue) > 65536 {
		return errors.New("clientstate: invalid publisher signing identity")
	}
	sealed, err := s.secrets.Seal(ctx, identityContext(scope, identity.ID, identity.PublicValue), identity.PrivateValue)
	if err != nil {
		return err
	}
	return s.database.queries.SavePublisherSigningIdentity(ctx, clientstatedb.SavePublisherSigningIdentityParams{
		ServerOrigin: s.controlEndpoint, Scope: scope, IdentityID: identity.ID, PublicValue: identity.PublicValue,
		StoredPrivate: sealed, UpdatedAt: s.database.now().UTC().UnixNano(),
	})
}

func (s *Store) RemovePublisherSigningIdentity(ctx context.Context, scope string) error {
	return s.database.queries.DeletePublisherSigningIdentity(ctx, clientstatedb.DeletePublisherSigningIdentityParams{ServerOrigin: s.controlEndpoint, Scope: scope})
}

// SystemState stores opaque encrypted state outside a server profile. a system
// publisher can open this database with ProtectionFile on macOS as well.
func (d *Database) SystemState(ctx context.Context, name string) ([]byte, bool, error) {
	if !validOpaqueValue(name, 256) {
		return nil, false, errors.New("clientstate: invalid system state name")
	}
	sealed, err := d.queries.GetSystemState(ctx, name)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	value, err := d.secrets.Open(ctx, "system-state:"+name, sealed)
	return value, true, err
}

func (d *Database) SaveSystemState(ctx context.Context, name string, value []byte) error {
	if !validOpaqueValue(name, 256) || len(value) > 1<<20 {
		return errors.New("clientstate: invalid system state")
	}
	sealed, err := d.secrets.Seal(ctx, "system-state:"+name, value)
	if err != nil {
		return err
	}
	return d.queries.SaveSystemState(ctx, clientstatedb.SaveSystemStateParams{Name: name, StoredValue: sealed, UpdatedAt: d.now().UTC().UnixNano()})
}

func (d *Database) RemoveSystemState(ctx context.Context, name string) error {
	return d.queries.DeleteSystemState(ctx, name)
}
