package state

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

type GetProjectServiceRequest struct {
	EnvironmentID                                              string
	PublisherGroup                                             string
	TeamID, ProjectKey, SourceFingerprint, Service, IdentityID string
	Now                                                        time.Time
}

// visitor lookup follows the applied resource binding, never a friendly name.
// reading the encrypted project document or its targets requires manager access.
func (d *Database) GetProjectService(ctx context.Context, r GetProjectServiceRequest) (result ServiceRecord, retErr error) {
	if !naming.ValidProjectKey(r.ProjectKey) || !fingerprintPattern.MatchString(r.SourceFingerprint) || !serviceName.MatchString(r.Service) {
		return result, ErrServiceAccess
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "read applied service", &retErr)()
	var id string
	err = tx.QueryRow(ctx, `SELECT service.service_id FROM control.applied_project_services service JOIN control.applied_projects project USING(team_id,project_key)
	    JOIN control.project_publisher_groups publisher_group ON publisher_group.id=service.group_id AND publisher_group.deleted_at IS NULL
	    LEFT JOIN control.environments environment ON environment.group_id=publisher_group.id
	    WHERE project.team_id=$1 AND project.project_key=$2 AND project.source_fingerprint=$3 AND service.service_id IS NOT NULL
	    AND service.service=CASE WHEN publisher_group.template_name='' AND publisher_group.environment_id IS NULL AND environment.id IS NULL THEN $4 ELSE publisher_group.id||'/'||$4 END
	    AND (($6<>'' AND publisher_group.environment_id=$6 AND environment.id=$6 AND environment.team_id=$1 AND environment.project_key=$2 AND environment.retired_at IS NULL)
	      OR ($6='' AND publisher_group.environment_id IS NULL AND environment.id IS NULL AND (($5='' AND publisher_group.template_name='') OR publisher_group.id=$5 OR EXISTS(SELECT 1 FROM control.publisher_group_names alias WHERE alias.group_id=publisher_group.id AND alias.name=$5))))`, r.TeamID, r.ProjectKey, r.SourceFingerprint, r.Service, r.PublisherGroup, r.EnvironmentID).Scan(&id)
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if _, _, err = privateVisitorAccess(ctx, tx, id, r.IdentityID, r.Now); err != nil {
		return result, err
	}
	row, err := controlstatedb.New(tx).GetService(ctx, id)
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	result, err = checkedServiceRecord(row)
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}
