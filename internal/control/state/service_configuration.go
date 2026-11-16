package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// declarations come from serviceConfiguration or normalizeServiceConfiguration,
// never ciphertext or an unnormalized caller value. json.Marshal orders map keys.
func serviceConfigurationDigest(declaration *ProjectServiceConfiguration) (string, error) {
	data, err := json.Marshal(declaration)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("tnl/service-configuration/v1\x00"), data...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func ValidServiceConfigurationDigest(digest string) bool {
	if len(digest) != 71 || !strings.HasPrefix(digest, "sha256:") {
		return false
	}
	for _, c := range digest[7:] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// configuration replacements require exactly one observed digest or an explicit
// unconditional choice. metadata-only updates do not replace configuration.
func (c ServiceUpdateConditions) ValidateConfiguration(replacement bool) error {
	if !replacement {
		if c.ConfigurationDigest != "" || c.UnconditionalConfiguration {
			return ErrProjectConfigurationInvalid
		}
		return nil
	}
	if c.UnconditionalConfiguration {
		if c.ConfigurationDigest != "" {
			return ErrProjectConfigurationInvalid
		}
		return nil
	}
	if !ValidServiceConfigurationDigest(c.ConfigurationDigest) {
		return ErrProjectConfigurationInvalid
	}
	return nil
}

func (d *Database) GetServiceConfiguration(ctx context.Context, serviceID, actorID string) (_ *ProjectServiceConfiguration, _ string, retErr error) {
	if !opaqueid.Valid(serviceID, opaqueid.ServicePrefix) {
		return nil, "", ErrServiceAccess
	}
	tx, err := d.beginServiceAccess(ctx, serviceReadOptions(ctx))
	if err != nil {
		return nil, "", err
	}
	defer rollback(ctx, tx, "get service configuration", &retErr)()
	row, err := serviceForManagement(ctx, tx, serviceID, actorID)
	if err != nil {
		return nil, "", err
	}
	if _, err := checkedServiceMetadata(row); err != nil {
		return nil, "", err
	}
	declaration, err := d.serviceConfiguration(ctx, controlstatedb.New(tx), serviceID)
	if err != nil {
		return nil, "", err
	}
	digest, err := serviceConfigurationDigest(declaration)
	if err != nil {
		return nil, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, "", err
	}
	return declaration, digest, nil
}

func serviceConfigurationContext(service string) string {
	return "service-configuration/" + service
}

func normalizeServiceConfiguration(name string, value *ProjectServiceConfiguration) (*ProjectServiceConfiguration, error) {
	data, err := json.Marshal(value)
	if err != nil || len(data) > 512<<10 {
		return nil, ErrProjectConfigurationInvalid
	}
	var normalized ProjectServiceConfiguration
	if err := json.Unmarshal(data, &normalized); err != nil {
		return nil, ErrProjectConfigurationInvalid
	}
	if err := normalizeAppliedProjectService(name, &normalized, true); err != nil {
		return nil, err
	}
	if normalized.Name != name {
		return nil, ErrProjectConfigurationInvalid
	}
	return &normalized, nil
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
	_, err = tx.Exec(ctx, `SELECT control.touch_visitor_policy($1)`, service)
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
	configurations, err := d.serviceConfigurations(ctx, q, []string{service})
	if err != nil {
		return nil, err
	}
	declaration, ok := configurations[service]
	if !ok {
		return nil, ErrServiceAccess
	}
	return declaration, nil
}

// serviceConfigurations uses the same owner validation and declaration decoding
// for point reads and routing snapshots. each deployment is opened once per read;
// no configuration or decrypted secret survives the caller's transaction.
func (d *Database) serviceConfigurations(ctx context.Context, q *controlstatedb.Queries, services []string) (map[string]*ProjectServiceConfiguration, error) {
	rows, err := q.ListServiceConfigurations(ctx, services)
	if err != nil {
		return nil, err
	}
	result := make(map[string]*ProjectServiceConfiguration, len(rows))
	var deployed []string
	for _, saved := range rows {
		if saved.AllocationOwned && (saved.LocalOwned || saved.DeploymentOwned) ||
			saved.DeploymentOwned && (saved.LocalOwned || saved.ConfigurationCiphertext != nil || saved.StorageKeyID.Valid) {
			return nil, ErrServiceAccess
		}
		if saved.DeploymentOwned {
			deployed = append(deployed, saved.ServiceID)
			continue
		}
		declaration, err := d.openServiceConfiguration(saved.ServiceID, saved.Service, saved.StorageKeyID.String, saved.ConfigurationCiphertext, saved.RequiredTemporaryApproval)
		if err != nil {
			return nil, err
		}
		if declaration == nil && (saved.LocalOwned || saved.AllocationOwned) {
			return nil, ErrServiceAccess
		}
		result[saved.ServiceID] = declaration
	}
	if len(deployed) == 0 {
		return result, nil
	}
	bindings, err := q.ListDeploymentServiceConfigurations(ctx, deployed)
	if err != nil {
		return nil, err
	}
	if len(bindings) != len(deployed) {
		return nil, ErrServiceAccess
	}
	opened := make(map[string]deploymentConfiguration)
	for _, binding := range bindings {
		deployment := binding.ControlDeployment
		c, ok := opened[deployment.ID]
		if !ok {
			c, err = d.openDeploymentConfiguration(deployment)
			if err != nil {
				return nil, err
			}
			opened[deployment.ID] = c
		}
		declaration, ok := c.Services[binding.Service]
		if !ok {
			return nil, ErrServiceAccess
		}
		if err := normalizeAppliedProjectService(binding.Service, &declaration, false); err != nil {
			return nil, errors.Join(ErrServiceAccess, err)
		}
		result[binding.ServiceID.String] = &declaration
	}
	return result, nil
}
