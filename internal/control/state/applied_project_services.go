package state

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
)

// apply can close or update several named services and local realizations. the
// team guard keeps their identity set stable. acquire the complete parent set
// before any mutation can publish audit/routing or change slot reservations;
// expiration holds one parent before those same clocks. new rows are private to
// this transaction and cannot be held by a concurrent run worker.
func lockAppliedProjectPublications(ctx context.Context, tx pgx.Tx, team, project string) error {
	_, err := tx.Exec(ctx, `SELECT service.id FROM control.services service
		WHERE service.id IN (
			SELECT service_id FROM control.applied_project_services WHERE team_id=$1 AND project_key=$2
			UNION SELECT service_id FROM control.local_project_services WHERE team_id=$1 AND project_key=$2)
		ORDER BY service.id FOR UPDATE OF service`, team, project)
	return err
}

func (d *Database) createAppliedService(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, r ApplyProjectConfigurationRequest, key, scope string, s ProjectServiceConfiguration, publisherPool bool) (string, error) {
	id, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(r.TeamID + "\x00" + r.ProjectKey + "\x00" + key))
	_, err = q.InsertService(ctx, controlstatedb.InsertServiceParams{ID: id, TeamID: r.TeamID, Name: s.Name, NameScope: scope, CreatedByIdentityID: r.ActorID, IdempotencyKey: "applied/" + id, RequestDigest: digest[:], Now: timestamptz(r.Now)})
	if err != nil {
		return "", projectConstraintError(err)
	}
	trust, err := appliedServiceTargetTrust(s.TargetTLS)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(trust)
	if err != nil {
		return "", err
	}
	_, err = tx.Exec(ctx, `UPDATE control.services SET protocol=$2,tls_metadata=$3::jsonb,publisher_pool=$4,
	    ephemeral=$5,require_post_quantum=COALESCE($6::boolean,require_post_quantum) WHERE id=$1`, id, s.Protocol, string(encoded), publisherPool, s.Ephemeral, s.RequirePostQuantum)
	if err != nil {
		return "", err
	}
	grant, err := opaqueid.New(opaqueid.ServiceGrantPrefix)
	if err != nil {
		return "", err
	}
	_, err = tx.Exec(ctx, `INSERT INTO control.visitor_grants(id,service_id,team_id,kind,identity_id,auto_owner,created_by_identity_id,idempotency_key,request_digest,created_at) VALUES($1,$2,$3,'identity',$4,true,$4,$5,$6,$7)`, grant, id, r.TeamID, r.ActorID, "applied-owner/"+id, digest[:], r.Now)
	return id, err
}

func (d *Database) updateAppliedService(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, id, scope string, s ProjectServiceConfiguration, publisherPool bool, now time.Time) error {
	row, err := q.LockService(ctx, id)
	if err != nil {
		return err
	}
	trust, err := appliedServiceTargetTrust(s.TargetTLS)
	if err != nil {
		return err
	}
	metadata := ServiceMetadata{Protocol: s.Protocol, TLS: trust, PublisherPool: publisherPool}
	saved, err := checkedServiceMetadata(row)
	if err != nil {
		return err
	}
	changed := !serviceMetadataMatches(saved, metadata) || row.PublisherPool != metadata.PublisherPool
	if saved.Protocol != s.Protocol || row.NameScope != scope {
		if _, err = tx.Exec(ctx, `UPDATE control.deployment_publisher_enrollment_services SET revoked_at=COALESCE(revoked_at,$2) WHERE service_id=$1`, id, now); err != nil {
			return err
		}
	}
	if s.RequirePostQuantum != nil && *s.RequirePostQuantum != row.RequirePostQuantum {
		// visitor TLS is captured for each run. changing it ends that run
		// without changing publisher-to-target trust or a broader grant.
		if _, err = tx.Exec(ctx, `UPDATE control.service_runs SET state='closed',closed_at=$2
			WHERE service_id=$1 AND closed_at IS NULL`, id, now); err != nil {
			return err
		}
	}
	encoded, err := json.Marshal(trust)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE control.services SET protocol=$2,tls_metadata=$3::jsonb,publisher_pool=$4,trust_revision=trust_revision+CASE WHEN $5 THEN 1 ELSE 0 END,
	    updated_at=$6,name=$7,name_scope=$8,ephemeral=$9,require_post_quantum=COALESCE($10::boolean,require_post_quantum) WHERE id=$1`, id, s.Protocol, string(encoded), metadata.PublisherPool, changed, now, s.Name, scope, s.Ephemeral, s.RequirePostQuantum)
	return projectConstraintError(err)
}

func appliedServiceTargetTrust(trust *ProjectTargetTLS) (*ServiceTargetTLS, error) {
	if trust == nil {
		return nil, nil
	}
	snapshot, err := (targettrust.Declaration{Hostname: trust.Hostname, CAPEM: []byte(trust.CAPEM), Digest: trust.Digest}).Snapshot()
	if err != nil {
		return nil, errors.Join(ErrProjectConfigurationInvalid, err)
	}
	return &ServiceTargetTLS{Hostname: snapshot.Hostname, PEM: string(snapshot.PEM), System: snapshot.System, Digest: snapshot.Digest}, nil
}

func (d *Database) revokeAppliedServicePublishers(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, s controlstatedb.ControlAppliedProjectService, now time.Time) error {
	if err := d.revokeProjectResourcePublishers(ctx, tx, q, s, now); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `DELETE FROM control.deployment_publisher_service_grants WHERE team_id=$1 AND project_key=$2 AND service=$3 AND deployment_id=$4`, s.TeamID, s.ProjectKey, s.Service, s.DeploymentID)
	return err
}

func (d *Database) revokeProjectResourcePublishers(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, s controlstatedb.ControlAppliedProjectService, now time.Time) error {
	if !s.ServiceID.Valid {
		return nil
	}
	if _, err := q.LockService(ctx, s.ServiceID.String); err != nil {
		return err
	}
	// a changed binding ends every affected run, including those using a
	// registered credential. that credential may still cover other services.
	if _, err := tx.Exec(ctx, `UPDATE control.service_runs SET state='closed',closed_at=$2
		WHERE service_id=$1 AND closed_at IS NULL`, s.ServiceID.String, now); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT id,publisher_identity_id FROM control.publisher_grants WHERE revoked_at IS NULL AND service_id=$1 ORDER BY publisher_identity_id,id`, s.ServiceID)
	if err != nil {
		return err
	}
	type grant struct{ id, publisher string }
	var grants []grant
	for rows.Next() {
		var g grant
		if err = rows.Scan(&g.id, &g.publisher); err != nil {
			rows.Close()
			return err
		}
		grants = append(grants, g)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, g := range grants {
		err = closeRevokedPrivatePublication(ctx, tx, q, s.ServiceID.String, g.publisher, g.id, now)
		if err != nil {
			return err
		}
		if _, err = q.RevokePublisherGrant(ctx, controlstatedb.RevokePublisherGrantParams{ID: g.id, PublisherIdentityID: g.publisher, Now: timestamptz(now)}); err != nil {
			return err
		}
	}
	return nil
}

func (d *Database) removeAppliedService(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, s controlstatedb.ControlAppliedProjectService, now time.Time) error {
	if err := d.revokeAppliedServicePublishers(ctx, tx, q, s, now); err != nil {
		return err
	}
	if err := d.retireProjectResource(ctx, tx, q, s, now); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `DELETE FROM control.applied_project_services WHERE team_id=$1 AND project_key=$2 AND service=$3 AND deployment_id IS NOT DISTINCT FROM $4`, s.TeamID, s.ProjectKey, s.Service, s.DeploymentID)
	return err
}

func (d *Database) retireProjectResource(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, s controlstatedb.ControlAppliedProjectService, now time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE control.deployment_publisher_enrollment_services SET revoked_at=COALESCE(revoked_at,$2)
		WHERE service_id=$1::text`, s.ServiceID, now); err != nil {
		return err
	}
	if s.ServiceID.Valid {
		if _, err := q.LockService(ctx, s.ServiceID.String); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE control.service_runs SET state='closed',closed_at=$2 WHERE service_id=$1 AND closed_at IS NULL`, s.ServiceID.String, now); err != nil {
			return err
		}
		if _, err := q.DeleteService(ctx, controlstatedb.DeleteServiceParams{ID: s.ServiceID.String, TeamID: s.TeamID, Now: timestamptz(now)}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE control.visitor_grants SET revoked_at=COALESCE(revoked_at,$2) WHERE service_id=$1`, s.ServiceID.String, now); err != nil {
			return err
		}
	}
	return nil
}

func (d *Database) reconcileAppliedVisitorGrant(ctx context.Context, tx pgx.Tx, s controlstatedb.ControlAppliedProjectService, actor string, enabled bool, now time.Time) error {
	var grant string
	if err := tx.QueryRow(ctx, `SELECT COALESCE(visitor_grant_id,'') FROM control.applied_project_services WHERE team_id=$1 AND project_key=$2 AND service=$3 AND deployment_id IS NOT DISTINCT FROM $4`, s.TeamID, s.ProjectKey, s.Service, s.DeploymentID).Scan(&grant); err != nil {
		return err
	}
	grant, err := reconcileProjectVisitorGrant(ctx, tx, s, actor, grant, enabled, now)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE control.applied_project_services SET visitor_grant_id=$4 WHERE team_id=$1 AND project_key=$2 AND service=$3 AND deployment_id IS NOT DISTINCT FROM $5`, s.TeamID, s.ProjectKey, s.Service, nullableText(grant), s.DeploymentID)
	return err
}

func reconcileProjectVisitorGrant(ctx context.Context, tx pgx.Tx, s controlstatedb.ControlAppliedProjectService, actor, grant string, enabled bool, now time.Time) (string, error) {
	if grant != "" {
		if enabled {
			return grant, nil
		}
		if _, err := tx.Exec(ctx, `UPDATE control.visitor_grants SET revoked_at=COALESCE(revoked_at,$2) WHERE id=$1`, grant, now); err != nil {
			return "", err
		}
		return "", nil
	}
	if !enabled || !s.ServiceID.Valid {
		return "", nil
	}
	id, err := opaqueid.New(opaqueid.ServiceGrantPrefix)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte("applied-team/" + id))
	_, err = tx.Exec(ctx, `INSERT INTO control.visitor_grants(id,service_id,team_id,kind,created_by_identity_id,idempotency_key,request_digest,created_at) VALUES($1,$2,$3,'team',$4,$1,$5,$6)`, id, s.ServiceID.String, s.TeamID, actor, digest[:], now)
	if err != nil {
		return "", err
	}
	return id, nil
}

func (d *Database) reconcileAppliedPublisherGrants(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, s controlstatedb.ControlAppliedProjectService, actor string, now time.Time) error {
	rows, err := tx.Query(ctx, `SELECT m.publisher_identity_id FROM control.deployment_publisher_members m JOIN control.publisher_identities p ON p.id=m.publisher_identity_id WHERE m.deployment_id=$1 AND p.revoked_at IS NULL ORDER BY p.id`, s.DeploymentID)
	if err != nil {
		return err
	}
	var members []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		members = append(members, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range members {
		if err = d.ensureDeploymentServiceGrant(ctx, tx, q, id, s, actor, now); err != nil {
			return err
		}
	}
	return nil
}

func (d *Database) ensureDeploymentServiceGrant(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, publisher string, s controlstatedb.ControlAppliedProjectService, actor string, now time.Time) error {
	if !s.ServiceID.Valid {
		return ErrProjectConfigurationInvalid
	}
	allowed, err := q.DeploymentPublisherServiceAllowed(ctx, controlstatedb.DeploymentPublisherServiceAllowedParams{PublisherID: publisher, DeploymentID: s.DeploymentID.String, Service: s.Service, ServiceID: s.ServiceID.String})
	if err != nil || !allowed {
		return err
	}
	var existing string
	err = tx.QueryRow(ctx, `SELECT assignment.grant_id FROM control.deployment_publisher_service_grants assignment WHERE assignment.publisher_identity_id=$1 AND assignment.team_id=$2 AND assignment.project_key=$3 AND assignment.service=$4 AND assignment.deployment_id=$5`, publisher, s.TeamID, s.ProjectKey, s.Service, s.DeploymentID).Scan(&existing)
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	scope := servicePublisherScope{s.TeamID, s.ServiceID.String}
	g, err := insertPublisherGrant(ctx, q, publisher, actor, scope, nil, now)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO control.deployment_publisher_service_grants(publisher_identity_id,team_id,project_key,service,grant_id,deployment_id) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(publisher_identity_id,team_id,project_key,service) DO UPDATE SET grant_id=EXCLUDED.grant_id`, publisher, s.TeamID, s.ProjectKey, s.Service, g.ID, s.DeploymentID)
	return err
}
