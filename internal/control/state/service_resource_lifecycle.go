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

// callers prelock their complete publication parent set first. closing a run
// changes shared relay reservations, so take this guard before any port inventory
// lock, including batches that mix removals with retained-service updates.
func lockAppliedPublicationReservations(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('tnl:relay-assignment-totals',0))`)
	return err
}

func (d *Database) createLocalService(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, r serviceResourceMutation, key, scope string, s LocalServiceDeclaration) (string, error) {
	issuer := publisherIssuer{IdentityID: r.ActorID}
	id, err := d.createLocalServiceResource(ctx, tx, q, r, key, scope, s, issuer)
	if err != nil {
		return id, err
	}
	// a local worktree's private listener retains its exact owner's access.
	// environment materialization never enters this local lifecycle.
	digest := sha256.Sum256([]byte(r.TeamID + "\x00" + r.ProjectKey + "\x00" + key))
	grant, err := opaqueid.New(opaqueid.ServiceGrantPrefix)
	if err != nil {
		return "", err
	}
	_, err = tx.Exec(ctx, `INSERT INTO control.visitor_grants(id,service_id,team_id,kind,identity_id,auto_owner,created_by_identity_id,idempotency_key,request_digest,created_at) VALUES($1,$2,$3,'identity',$4,true,$4,$5,$6,$7)`, grant, id, r.TeamID, issuer.IdentityID, "applied-owner/"+id, digest[:], r.Now)
	return id, err
}

func (d *Database) createLocalServiceResource(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, r serviceResourceMutation, key, scope string, s LocalServiceDeclaration, issuer publisherIssuer) (string, error) {
	id, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(r.TeamID + "\x00" + r.ProjectKey + "\x00" + key))
	_, err = q.InsertService(ctx, controlstatedb.InsertServiceParams{ID: id, TeamID: r.TeamID, Name: s.Name, NameScope: scope, CreatedByIdentityID: nullableText(issuer.IdentityID), CreatedByMachineID: nullableText(issuer.MachineID), ProvisioningGrantID: nullableText(issuer.ProvisioningGrantID), IdempotencyKey: "applied/" + id, RequestDigest: digest[:], Now: timestamptz(r.Now)})
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
	_, err = tx.Exec(ctx, `UPDATE control.services SET protocol=$2,tls_metadata=$3::jsonb,publisher_pool=false WHERE id=$1`, id, s.Protocol, string(encoded))
	if err != nil {
		return "", err
	}
	return id, nil
}

func (d *Database) updateLocalServiceResource(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, id, scope string, s LocalServiceDeclaration, now time.Time) error {
	row, err := q.LockService(ctx, id)
	if err != nil {
		return err
	}
	trust, err := appliedServiceTargetTrust(s.TargetTLS)
	if err != nil {
		return err
	}
	metadata := ServiceMetadata{Protocol: s.Protocol, TLS: trust}
	saved, err := checkedServiceMetadata(row)
	if err != nil {
		return err
	}
	changed := !serviceMetadataMatches(saved, metadata) || row.PublisherPool != metadata.PublisherPool
	encoded, err := json.Marshal(trust)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE control.services SET protocol=$2,tls_metadata=$3::jsonb,publisher_pool=$4,trust_revision=trust_revision+CASE WHEN $5 THEN 1 ELSE 0 END,updated_at=$6,name=$7,name_scope=$8 WHERE id=$1`, id, s.Protocol, string(encoded), metadata.PublisherPool, changed, now, s.Name, scope)
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
	_, err := tx.Exec(ctx, `DELETE FROM control.publisher_group_service_grants WHERE team_id=$1 AND project_key=$2 AND service=$3`, s.TeamID, s.ProjectKey, s.Service)
	return err
}

func (d *Database) revokeProjectResourcePublishers(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, s controlstatedb.ControlAppliedProjectService, now time.Time) error {
	rows, err := tx.Query(ctx, `SELECT id,publisher_identity_id FROM control.publisher_grants WHERE revoked_at IS NULL AND (($1::text IS NOT NULL AND service_id=$1) OR ($2::text IS NOT NULL AND public_url_id=$2)) ORDER BY publisher_identity_id,id`, s.ServiceID, s.PublicURLID)
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
		if s.ServiceID.Valid {
			err = closeRevokedPrivatePublication(ctx, tx, q, s.ServiceID.String, g.publisher, g.id, now)
		} else {
			err = closeRevokedPublicPublications(ctx, tx, q, g.publisher, g.id, now)
		}
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
	_, err := tx.Exec(ctx, `DELETE FROM control.applied_project_services WHERE team_id=$1 AND project_key=$2 AND service=$3`, s.TeamID, s.ProjectKey, s.Service)
	return err
}

func (d *Database) retireProjectResource(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, s controlstatedb.ControlAppliedProjectService, now time.Time) error {
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
	} else if s.PublicURLID.Valid {
		u, err := q.LockPublicURLForRun(ctx, s.PublicURLID.String)
		if err != nil {
			return err
		}
		pending := pendingIngressRoutingTableEvents{}
		if err = closeOpenPublishRun(ctx, q, &pending, u, now, "configuration_removed"); err != nil {
			return err
		}
		if _, err = q.DeletePublicURL(ctx, controlstatedb.DeletePublicURLParams{PublicURLID: u.ID, ExpectedMutationRevision: u.MutationRevision, DeletedAt: timestamptz(now)}); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE control.visitor_grants SET revoked_at=COALESCE(revoked_at,$2) WHERE public_url_id=$1`, u.ID, now); err != nil {
			return err
		}
		if err = pending.publish(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

func reconcileProjectVisitorGrant(ctx context.Context, tx pgx.Tx, s controlstatedb.ControlAppliedProjectService, actor, grant string, enabled bool, now time.Time) (string, error) {
	return reconcileProjectVisitorGrantForIssuer(ctx, tx, s, publisherIssuer{IdentityID: actor}, grant, enabled, now)
}

func reconcileProjectVisitorGrantForIssuer(ctx context.Context, tx pgx.Tx, s controlstatedb.ControlAppliedProjectService, actor publisherIssuer, grant string, enabled bool, now time.Time) (string, error) {
	if grant != "" {
		if enabled {
			return grant, nil
		}
		table := "control.visitor_grants"
		if s.ServiceID.Valid {
			table = "control.visitor_grants"
		}
		if _, err := tx.Exec(ctx, `UPDATE `+table+` SET revoked_at=COALESCE(revoked_at,$2) WHERE id=$1`, grant, now); err != nil {
			return "", err
		}
		return "", nil
	}
	if !enabled || !s.ServiceID.Valid && !s.PublicURLID.Valid {
		return "", nil
	}
	prefix := opaqueid.SharePrefix
	if s.ServiceID.Valid {
		prefix = opaqueid.ServiceGrantPrefix
	}
	id, err := opaqueid.New(prefix)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte("applied-team/" + id))
	if s.ServiceID.Valid {
		_, err = tx.Exec(ctx, `INSERT INTO control.visitor_grants(id,service_id,team_id,kind,created_by_identity_id,created_by_machine_id,provisioning_grant_id,idempotency_key,request_digest,created_at) VALUES($1,$2,$3,'team',$4,$5,$6,$1,$7,$8)`, id, s.ServiceID.String, s.TeamID, nullableText(actor.IdentityID), nullableText(actor.MachineID), nullableText(actor.ProvisioningGrantID), digest[:], now)
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO control.visitor_grants(id,public_url_id,team_id,kind,created_by_identity_id,idempotency_key,request_digest,created_at) VALUES($1,$2,$3,'team',$4,$1,$5,$6)`, id, s.PublicURLID.String, s.TeamID, actor.IdentityID, digest[:], now)
	}
	if err != nil {
		return "", err
	}
	return id, nil
}
