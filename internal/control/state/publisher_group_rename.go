package controlstate

import (
	"context"
	"encoding/json"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

// rename changes the desired selector, not the durable namespace or credentials.
// historical names remain bound to this ID so a stale deployment cannot enroll
// into an unrelated group merely because its old key was reused.
func (d *Database) RenamePublisherGroup(ctx context.Context, team, project, old, name, actor string, expected int64, now time.Time) (result AppliedProjectConfiguration, retErr error) {
	if !naming.ValidProjectKey(project) || !naming.ValidServiceName(old) || !naming.ValidServiceName(name) || name == "local" || old == "local" || expected < 1 || expected == 1<<63-1 {
		return result, ErrProjectConfigurationInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "rename publisher group", &retErr)()
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, team); err != nil {
		return result, publisherLookupError(err, ErrPrivateServiceAccess)
	}
	if err = privateServiceManager(ctx, tx, team, actor); err != nil {
		return result, err
	}
	row, err := q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: team, ProjectKey: project})
	if err != nil {
		return result, publisherLookupError(err, ErrPrivateServiceAccess)
	}
	var id, current string
	err = tx.QueryRow(ctx, `SELECT g.id,g.name FROM control.project_publisher_groups g JOIN control.publisher_group_names alias ON alias.group_id=g.id WHERE alias.team_id=$1 AND alias.project_key=$2 AND alias.name=$3 AND g.deleted_at IS NULL FOR UPDATE OF g`, team, project, old).Scan(&id, &current)
	if err != nil {
		return result, publisherLookupError(err, ErrPublisherGroup)
	}
	c, err := d.openAppliedProject(row)
	if err != nil {
		return result, err
	}
	if current == name {
		result, err = d.appliedProjectStatus(ctx, tx, row, c)
		if err != nil {
			return result, err
		}
		return result, tx.Commit(ctx)
	}
	if current != old || row.Revision != expected {
		return result, ErrProjectConfigurationStale
	}
	if _, exists := c.Publishers[name]; exists {
		return result, ErrPrivateServiceConflict
	}
	if err = claimPublisherGroupName(ctx, tx, team, project, name, id, now); err != nil {
		return result, err
	}
	c.Publishers[name] = c.Publishers[old]
	delete(c.Publishers, old)
	for key, service := range c.Services {
		if service.Publisher == old {
			service.Publisher = name
			c.Services[key] = service
		}
	}
	c, hash, err := NormalizeProjectConfiguration(c)
	if err != nil {
		return result, err
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		return result, err
	}
	sealed, err := d.storageKey.Seal(appliedProjectContext(team, project), encoded)
	if err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, `UPDATE control.project_publisher_groups SET name=$2 WHERE id=$1`, id, name); err != nil {
		return result, projectConstraintError(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE control.applied_project_services SET desired_revision=$3 WHERE team_id=$1 AND project_key=$2`, team, project, row.Revision+1); err != nil {
		return result, err
	}
	if _, err = tx.Exec(ctx, `UPDATE control.applied_projects SET revision=revision+1,configuration_hash=$3,configuration_ciphertext=$4,storage_key_id=$5,updated_at=$6 WHERE team_id=$1 AND project_key=$2`, team, project, hash, sealed, d.storageKey.CurrentID(), now); err != nil {
		return result, err
	}
	if err = recordPublisherGroupUpdate(ctx, tx, id, actor, "", "rename/"+old+"/"+name, now); err != nil {
		return result, err
	}
	row.Revision++
	row.ConfigurationHash = hash
	result, err = d.appliedProjectStatus(ctx, tx, row, c)
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}
