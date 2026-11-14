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

func serviceConfigurationContext(service string) string {
	return "service-configuration/" + service
}

// service-owned declarations need no project or worktree. applied remote services
// instead read their exact binding from the encrypted deployment configuration.
// callers hold the service and its authority parents through the save.
func (d *Database) saveServiceConfiguration(ctx context.Context, tx pgx.Tx, service string, value ProjectServiceConfiguration) error {
	q := controlstatedb.New(tx)
	row, err := q.GetServiceConfiguration(ctx, service)
	if err != nil {
		return err
	}
	if row.DeploymentOwned || row.LocalOwned && row.AllocationOwned {
		return ErrServiceAccess
	}
	if err := normalizeAppliedProjectService(row.Service, &value, true); err != nil {
		return err
	}
	previous, err := d.openServiceConfiguration(service, row.Service, row.StorageKeyID.String, row.ConfigurationCiphertext, row.RequiredTemporaryApproval)
	if err != nil {
		return err
	}
	if row.AllocationOwned && previous == nil {
		return ErrServiceAccess
	}
	if reflect.DeepEqual(previous, &value) {
		return nil
	}
	// creation saves before inserting the allocation association. afterward,
	// only an exact normalized retry can reuse that immutable declaration.
	if row.AllocationOwned {
		return ErrServiceConflict
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > 512<<10 {
		return ErrProjectConfigurationInvalid
	}
	sealed, err := d.storageKey.Seal(serviceConfigurationContext(service), data)
	if err != nil {
		return err
	}
	updated, err := q.SetServiceConfiguration(ctx, controlstatedb.SetServiceConfigurationParams{ServiceID: service, Ciphertext: sealed, StorageKeyID: text(d.storageKey.CurrentID())})
	if err != nil {
		return err
	}
	if updated != 1 {
		return ErrProjectConfigurationStale
	}
	var previousHTTP *config.HTTPService
	if previous != nil {
		previousHTTP = serviceHTTPRequestPolicy(previous.HTTP)
	}
	if reflect.DeepEqual(previousHTTP, serviceHTTPRequestPolicy(value.HTTP)) {
		return nil
	}
	_, err = tx.Exec(ctx, `SELECT control.touch_visitor_policy('service',$1)`, service)
	return err
}

func (d *Database) openServiceConfiguration(service, name, key string, sealed []byte, requiredApproval string) (*ProjectServiceConfiguration, error) {
	if len(sealed) == 0 {
		if key != "" || requiredApproval != "" {
			return nil, ErrServiceAccess
		}
		return nil, nil
	}
	data, _, err := d.storageKey.Open(key, serviceConfigurationContext(service), sealed)
	if err != nil {
		return nil, errors.Join(ErrServiceAccess, err)
	}
	if len(data) > 512<<10 {
		return nil, ErrServiceAccess
	}
	var declaration *ProjectServiceConfiguration
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&declaration); err != nil {
		return nil, errors.Join(ErrServiceAccess, err)
	}
	if declaration == nil || decoder.Decode(new(any)) != io.EOF {
		return nil, ErrServiceAccess
	}
	if err := normalizeAppliedProjectService(name, declaration, true); err != nil {
		return nil, errors.Join(ErrServiceAccess, err)
	}
	if requiredApproval != "" {
		mode := "restricted"
		if declaration.HTTP != nil && declaration.HTTP.Access != nil {
			mode = declaration.HTTP.Access.VisitorMode()
		}
		if mode != requiredApproval {
			return nil, ErrServiceAccess
		}
	}
	return declaration, nil
}

func serviceHTTPRequestPolicy(value *config.HTTPService) *config.HTTPService {
	if value == nil || value.Access == nil && value.Limits == nil {
		return nil
	}
	return &config.HTTPService{Access: value.Access, Limits: value.Limits}
}

func (d *Database) serviceConfiguration(ctx context.Context, q *controlstatedb.Queries, service string) (*ProjectServiceConfiguration, error) {
	saved, err := q.GetServiceConfiguration(ctx, service)
	if err != nil {
		return nil, publisherLookupError(err, ErrServiceAccess)
	}
	if saved.AllocationOwned && (saved.LocalOwned || saved.DeploymentOwned) ||
		saved.DeploymentOwned && (saved.LocalOwned || saved.ConfigurationCiphertext != nil || saved.StorageKeyID.Valid) {
		return nil, ErrServiceAccess
	}
	if !saved.DeploymentOwned {
		declaration, err := d.openServiceConfiguration(service, saved.Service, saved.StorageKeyID.String, saved.ConfigurationCiphertext, saved.RequiredTemporaryApproval)
		if err == nil && declaration == nil && (saved.LocalOwned || saved.AllocationOwned) {
			return nil, ErrServiceAccess
		}
		return declaration, err
	}
	row, err := q.GetDeploymentServiceConfiguration(ctx, text(service))
	if err != nil {
		return nil, publisherLookupError(err, ErrServiceAccess)
	}
	c, err := d.openDeploymentConfiguration(row.ControlDeployment)
	if err != nil {
		return nil, err
	}
	declaration, ok := c.Services[row.Service]
	if !ok {
		return nil, ErrServiceAccess
	}
	if err := normalizeAppliedProjectService(row.Service, &declaration, false); err != nil {
		return nil, errors.Join(ErrServiceAccess, err)
	}
	return &declaration, nil
}
