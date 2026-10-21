package controlstate

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

type GetProjectPrivateServiceRequest struct {
	TeamID, ProjectKey, SourceFingerprint, Service, IdentityID string
	Now                                                        time.Time
}

// visitor lookup follows the applied resource binding, never a friendly name.
// reading the encrypted project document or its targets requires manager access.
func (d *Database) GetProjectPrivateService(ctx context.Context, r GetProjectPrivateServiceRequest) (result PrivateServiceRecord, retErr error) {
	if !naming.ValidProjectKey(r.ProjectKey) || !fingerprintPattern.MatchString(r.SourceFingerprint) || !privateServiceName.MatchString(r.Service) {
		return result, ErrPrivateServiceAccess
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "read applied private service", &retErr)()
	var id string
	err = tx.QueryRow(ctx, `SELECT service.private_service_id FROM control.applied_project_services service JOIN control.applied_projects project USING(team_id,project_key)
	    JOIN control.project_publisher_groups publisher_group ON publisher_group.id=service.group_id AND publisher_group.deleted_at IS NULL
	    WHERE project.team_id=$1 AND project.project_key=$2 AND project.source_fingerprint=$3 AND service.service=$4 AND service.private_service_id IS NOT NULL`, r.TeamID, r.ProjectKey, r.SourceFingerprint, r.Service).Scan(&id)
	if err != nil {
		return result, publisherLookupError(err, ErrPrivateServiceAccess)
	}
	if _, _, err = privateVisitorAccess(ctx, tx, id, r.IdentityID, r.Now); err != nil {
		return result, err
	}
	row, err := controlstatedb.New(tx).GetPrivateService(ctx, id)
	if err != nil {
		return result, publisherLookupError(err, ErrPrivateServiceAccess)
	}
	return privateServiceRecord(row), tx.Commit(ctx)
}
