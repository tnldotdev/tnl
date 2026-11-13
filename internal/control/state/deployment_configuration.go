package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// publisher assignments and acknowledgements use this deployment's saved facts,
// not another deployment's targets or the project's apply revision.
type deploymentConfiguration struct {
	Namespace string                                 `json:"namespace"`
	Settings  ProjectPublisherGroup                  `json:"settings"`
	Services  map[string]ProjectServiceConfiguration `json:"services"`
}

func deploymentConfigurationContext(id string) string { return "deployment-configuration/" + id }

func (d *Database) saveDeploymentConfiguration(ctx context.Context, tx pgx.Tx, id, name string, c ProjectConfiguration) error {
	row, err := controlstatedb.New(tx).LockProjectPublisherGroup(ctx, id)
	if err != nil {
		return err
	}
	return d.writeDeploymentConfiguration(ctx, tx, row, projectDeploymentConfiguration(row.Namespace, name, c))
}

func projectDeploymentConfiguration(namespace, name string, c ProjectConfiguration) deploymentConfiguration {
	snapshot := deploymentConfiguration{
		Namespace: namespace,
		Settings:  c.PublisherGroups[name],
		Services:  map[string]ProjectServiceConfiguration{},
	}
	for key, service := range c.Services {
		if service.PublisherGroup == name {
			snapshot.Services[key] = service
		}
	}
	return snapshot
}

func (d *Database) writeDeploymentConfiguration(ctx context.Context, tx pgx.Tx, row controlstatedb.ControlProjectPublisherGroup, snapshot deploymentConfiguration) error {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	if len(data) > 512<<10 {
		return ErrProjectConfigurationInvalid
	}
	digest := sha256.Sum256(data)
	hash := hex.EncodeToString(digest[:])
	if row.ConfigurationHash != hash {
		if row.Revision == 1<<63-1 {
			return ErrProjectConfigurationStale
		}
		sealed, err := d.storageKey.Seal(deploymentConfigurationContext(row.ID), data)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE control.project_publisher_groups SET revision=revision+1,
			configuration_hash=$2,configuration_ciphertext=$3,storage_key_id=$4 WHERE id=$1`,
			row.ID, hash, sealed, d.storageKey.CurrentID()); err != nil {
			return err
		}
		row.Revision++
	}
	_, err = tx.Exec(ctx, `UPDATE control.applied_project_services SET desired_revision=$2 WHERE group_id=$1`, row.ID, row.Revision)
	return err
}

func (d *Database) openDeploymentConfiguration(row controlstatedb.ControlProjectPublisherGroup) (deploymentConfiguration, error) {
	var c deploymentConfiguration
	if row.Revision < 1 || !row.StorageKeyID.Valid {
		return c, ErrPublisherGroup
	}
	data, _, err := d.storageKey.Open(row.StorageKeyID.String, deploymentConfigurationContext(row.ID), row.ConfigurationCiphertext)
	if err != nil {
		return c, err
	}
	if err = json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("decode deployment configuration: %w", err)
	}
	return c, nil
}
