package controlstate

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/trafficlimits"
)

// apply can close or update several named services and local realizations. the
// team guard keeps their identity set stable. acquire the complete parent set
// before any mutation can publish audit/routing or change slot reservations;
// expiration holds one parent before those same clocks. new rows are private to
// this transaction and cannot be held by a concurrent run worker.
func lockAppliedProjectPublications(ctx context.Context, tx pgx.Tx, team, project string) error {
	if _, err := tx.Exec(ctx, `SELECT service.id FROM control.private_services service
		WHERE service.id IN (
			SELECT private_service_id FROM control.applied_project_services WHERE team_id=$1 AND project_key=$2
			UNION SELECT private_service_id FROM control.local_project_services WHERE team_id=$1 AND project_key=$2)
		ORDER BY service.id FOR UPDATE OF service`, team, project); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `SELECT service.id FROM control.public_urls service
		WHERE service.id IN (
			SELECT public_url_id FROM control.applied_project_services WHERE team_id=$1 AND project_key=$2
			UNION SELECT public_url_id FROM control.local_project_services WHERE team_id=$1 AND project_key=$2)
		ORDER BY service.id FOR NO KEY UPDATE OF service`, team, project)
	return err
}

func (d *Database) createAppliedPrivateService(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, r ApplyProjectConfigurationRequest, key, scope string, s ProjectServiceConfiguration) (string, error) {
	id, err := opaqueid.New(opaqueid.PrivateServicePrefix)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(r.TeamID + "\x00" + r.ProjectKey + "\x00" + key))
	_, err = q.InsertPrivateService(ctx, controlstatedb.InsertPrivateServiceParams{ID: id, TeamID: r.TeamID, Name: s.Name, NameScope: scope, CreatedByIdentityID: r.ActorID, IdempotencyKey: "applied/" + id, RequestDigest: digest[:], Now: timestamptz(r.Now)})
	if err != nil {
		return "", projectConstraintError(err)
	}
	trust, err := appliedPrivateTargetTrust(s.TargetTLS)
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(trust)
	if err != nil {
		return "", err
	}
	_, err = tx.Exec(ctx, `UPDATE control.private_services SET protocol=$2,tls_metadata=$3::jsonb,publisher_pool=$4 WHERE id=$1`, id, s.Protocol, string(encoded), s.Publisher != "local")
	if err != nil {
		return "", err
	}
	grant, err := opaqueid.New(opaqueid.PrivateServiceGrantPrefix)
	if err != nil {
		return "", err
	}
	_, err = tx.Exec(ctx, `INSERT INTO control.private_service_grants(id,private_service_id,team_id,kind,identity_id,auto_owner,created_by_identity_id,idempotency_key,request_digest,created_at) VALUES($1,$2,$3,'identity',$4,true,$4,$5,$6,$7)`, grant, id, r.TeamID, r.ActorID, "applied-owner/"+id, digest[:], r.Now)
	return id, err
}

func (d *Database) updateAppliedPrivateService(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, id, scope string, s ProjectServiceConfiguration, now time.Time) error {
	row, err := q.LockPrivateService(ctx, id)
	if err != nil {
		return err
	}
	trust, err := appliedPrivateTargetTrust(s.TargetTLS)
	if err != nil {
		return err
	}
	metadata := PrivateServiceMetadata{Protocol: s.Protocol, TLS: trust, PublisherPool: s.Publisher != "local"}
	saved, err := checkedPrivateMetadata(row)
	if err != nil {
		return err
	}
	changed := !privateMetadataMatches(saved, metadata) || row.PublisherPool != metadata.PublisherPool
	encoded, err := json.Marshal(trust)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE control.private_services SET protocol=$2,tls_metadata=$3::jsonb,publisher_pool=$4,trust_revision=trust_revision+CASE WHEN $5 THEN 1 ELSE 0 END,updated_at=$6,name=$7,name_scope=$8 WHERE id=$1`, id, s.Protocol, string(encoded), metadata.PublisherPool, changed, now, s.Name, scope)
	return projectConstraintError(err)
}

func appliedPrivateTargetTrust(trust *ProjectTargetTLS) (*PrivateServiceTLS, error) {
	if trust == nil {
		return nil, nil
	}
	snapshot, err := (projectconfig.TargetTrustSnapshot{Hostname: trust.Hostname, CAPEM: []byte(trust.CAPEM), Digest: trust.Digest}).PrivateSnapshot()
	if err != nil {
		return nil, errors.Join(ErrProjectConfigurationInvalid, err)
	}
	return &PrivateServiceTLS{Hostname: snapshot.Hostname, PEM: string(snapshot.PEM), System: snapshot.System, Digest: snapshot.Digest}, nil
}

// resolve names without evaluating source files. apply repeats this read under
// its mutation transaction; the HTTP boundary uses it before hostname authorization.
func (d *Database) ResolveProjectConfiguration(ctx context.Context, team, actor string, input ProjectConfiguration) (result ProjectConfiguration, retErr error) {
	c, _, err := NormalizeProjectConfiguration(input)
	if err != nil {
		return result, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "resolve project configuration", &retErr)()
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, team); err != nil {
		return result, publisherLookupError(err, ErrPrivateServiceAccess)
	}
	if err = privateServiceManager(ctx, tx, team, actor); err != nil {
		return result, err
	}
	return c, tx.Commit(ctx)
}

// use the same exact grants, encrypted IP snapshots and routing invalidation as
// the complete visitor-access API, within the apply transaction.
func (d *Database) reconcileAppliedPublicSettings(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, id string, p *ProjectServicePublicURL, now time.Time) error {
	u, err := q.LockPublicURLForRun(ctx, id)
	if err != nil {
		return err
	}
	modeChanged := u.AccessMode != p.Access.Mode
	if modeChanged {
		n, err := q.SetPublicURLAccessMode(ctx, controlstatedb.SetPublicURLAccessModeParams{PublicURLID: id, AccessMode: p.Access.Mode, ExpectedRevision: u.MutationRevision, Now: timestamptz(now)})
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrPublicURLMutationStale
		}
	}
	if err = q.RevokeVisitorIPGrants(ctx, controlstatedb.RevokeVisitorIPGrantsParams{PublicURLID: id, RevokedAt: timestamptz(now)}); err != nil {
		return err
	}
	if err = q.MarkVisitorIPSet(ctx, id); err != nil {
		return err
	}
	for _, value := range p.Access.IP {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return ErrProjectConfigurationInvalid
		}
		grant, err := opaqueid.New(opaqueid.SharePrefix)
		if err != nil {
			return err
		}
		sealed, err := d.storageKey.Seal(ipGrantContext(id, grant), []byte(prefix.String()))
		if err != nil {
			return err
		}
		if err = q.CreateVisitorIPGrant(ctx, controlstatedb.CreateVisitorIPGrantParams{ID: grant, PublicURLID: id, PrefixCiphertext: sealed, StorageKeyID: d.storageKey.CurrentID(), CreatedAt: timestamptz(now)}); err != nil {
			return err
		}
	}
	return d.refreshVisitorIPPolicy(ctx, q, id, now, !modeChanged)
}

func (d *Database) appliedProjectTraffic(ctx context.Context, tx pgx.Tx, url string, fallback *trafficlimits.Selection) (*trafficlimits.Selection, error) {
	var team, project, service string
	err := tx.QueryRow(ctx, `SELECT team_id,project_key,service FROM control.applied_project_services WHERE public_url_id=$1`, url).Scan(&team, &project, &service)
	if errors.Is(err, pgx.ErrNoRows) {
		return fallback, nil
	}
	if err != nil {
		return nil, err
	}
	// the caller holds the team guard and URL lock. do not reverse the apply
	// project's lock order by locking its project row after that URL.
	var row controlstatedb.ControlAppliedProject
	err = tx.QueryRow(ctx, `SELECT team_id,project_key,source_fingerprint,revision,configuration_hash,configuration_ciphertext,storage_key_id,created_by_identity_id,updated_at FROM control.applied_projects WHERE team_id=$1 AND project_key=$2`, team, project).Scan(&row.TeamID, &row.ProjectKey, &row.SourceFingerprint, &row.Revision, &row.ConfigurationHash, &row.ConfigurationCiphertext, &row.StorageKeyID, &row.CreatedByIdentityID, &row.UpdatedAt)
	if err != nil {
		return nil, err
	}
	c, err := d.openAppliedProject(row)
	if err != nil {
		return nil, err
	}
	s, ok := c.Services[service]
	if !ok || s.PublicURL == nil {
		return nil, ErrProjectConfigurationStale
	}
	if s.PublicURL.Limits == nil {
		return nil, nil
	}
	return s.PublicURL.Limits.Traffic, nil
}

func (d *Database) revokeAppliedServicePublishers(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, s controlstatedb.ControlAppliedProjectService, now time.Time) error {
	if err := d.revokeProjectResourcePublishers(ctx, tx, q, s, now); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `DELETE FROM control.publisher_group_service_grants WHERE team_id=$1 AND project_key=$2 AND service=$3`, s.TeamID, s.ProjectKey, s.Service)
	return err
}

func (d *Database) revokeProjectResourcePublishers(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, s controlstatedb.ControlAppliedProjectService, now time.Time) error {
	rows, err := tx.Query(ctx, `SELECT id,publisher_identity_id FROM control.publisher_grants WHERE revoked_at IS NULL AND (($1::text IS NOT NULL AND private_service_id=$1) OR ($2::text IS NOT NULL AND public_url_id=$2)) ORDER BY publisher_identity_id,id`, s.PrivateServiceID, s.PublicURLID)
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
		if s.PrivateServiceID.Valid {
			err = closeRevokedPrivatePublication(ctx, tx, q, s.PrivateServiceID.String, g.publisher, g.id, now)
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
	if s.PrivateServiceID.Valid {
		if _, err := q.LockPrivateService(ctx, s.PrivateServiceID.String); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE control.private_service_runs SET state='closed',closed_at=$2 WHERE private_service_id=$1 AND closed_at IS NULL`, s.PrivateServiceID.String, now); err != nil {
			return err
		}
		if _, err := q.DeletePrivateService(ctx, controlstatedb.DeletePrivateServiceParams{ID: s.PrivateServiceID.String, TeamID: s.TeamID, Now: timestamptz(now)}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE control.private_service_grants SET revoked_at=COALESCE(revoked_at,$2) WHERE private_service_id=$1`, s.PrivateServiceID.String, now); err != nil {
			return err
		}
		if err := privateRoutingTombstone(ctx, q, s.PrivateServiceID.String, now); err != nil {
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

func (d *Database) reconcileAppliedVisitorGrant(ctx context.Context, tx pgx.Tx, s controlstatedb.ControlAppliedProjectService, actor string, enabled bool, now time.Time) error {
	var grant string
	if err := tx.QueryRow(ctx, `SELECT COALESCE(visitor_grant_id,'') FROM control.applied_project_services WHERE team_id=$1 AND project_key=$2 AND service=$3`, s.TeamID, s.ProjectKey, s.Service).Scan(&grant); err != nil {
		return err
	}
	grant, err := reconcileProjectVisitorGrant(ctx, tx, s, actor, grant, enabled, now)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE control.applied_project_services SET visitor_grant_id=$4 WHERE team_id=$1 AND project_key=$2 AND service=$3`, s.TeamID, s.ProjectKey, s.Service, nullableText(grant))
	return err
}

func reconcileProjectVisitorGrant(ctx context.Context, tx pgx.Tx, s controlstatedb.ControlAppliedProjectService, actor, grant string, enabled bool, now time.Time) (string, error) {
	if grant != "" {
		if enabled {
			return grant, nil
		}
		table := "control.visitor_grants"
		if s.PrivateServiceID.Valid {
			table = "control.private_service_grants"
		}
		if _, err := tx.Exec(ctx, `UPDATE `+table+` SET revoked_at=COALESCE(revoked_at,$2) WHERE id=$1`, grant, now); err != nil {
			return "", err
		}
		return "", nil
	}
	if !enabled || !s.PrivateServiceID.Valid && !s.PublicURLID.Valid {
		return "", nil
	}
	prefix := opaqueid.SharePrefix
	if s.PrivateServiceID.Valid {
		prefix = opaqueid.PrivateServiceGrantPrefix
	}
	id, err := opaqueid.New(prefix)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte("applied-team/" + id))
	if s.PrivateServiceID.Valid {
		_, err = tx.Exec(ctx, `INSERT INTO control.private_service_grants(id,private_service_id,team_id,kind,created_by_identity_id,idempotency_key,request_digest,created_at) VALUES($1,$2,$3,'team',$4,$1,$5,$6)`, id, s.PrivateServiceID.String, s.TeamID, actor, digest[:], now)
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO control.visitor_grants(id,public_url_id,team_id,kind,created_by_identity_id,idempotency_key,request_digest,created_at) VALUES($1,$2,$3,'team',$4,$1,$5,$6)`, id, s.PublicURLID.String, s.TeamID, actor, digest[:], now)
	}
	if err != nil {
		return "", err
	}
	return id, nil
}

func (d *Database) reconcileAppliedPublisherGrants(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, s controlstatedb.ControlAppliedProjectService, actor string, now time.Time) error {
	rows, err := tx.Query(ctx, `SELECT m.publisher_identity_id FROM control.publisher_group_members m JOIN control.publisher_identities p ON p.id=m.publisher_identity_id WHERE m.group_id=$1 AND p.revoked_at IS NULL ORDER BY p.id`, s.GroupID)
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
		if err = d.ensureGroupServiceGrant(ctx, tx, q, id, s, actor, now); err != nil {
			return err
		}
	}
	return nil
}

func (d *Database) ensureGroupServiceGrant(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, publisher string, s controlstatedb.ControlAppliedProjectService, actor string, now time.Time) error {
	var existing string
	err := tx.QueryRow(ctx, `SELECT assignment.grant_id FROM control.publisher_group_service_grants assignment WHERE assignment.publisher_identity_id=$1 AND assignment.team_id=$2 AND assignment.project_key=$3 AND assignment.service=$4`, publisher, s.TeamID, s.ProjectKey, s.Service).Scan(&existing)
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	scope := publisherScopeForAppliedService(s)
	g, err := insertPublisherGrant(ctx, q, publisher, actor, scope, nil, now)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO control.publisher_group_service_grants(publisher_identity_id,team_id,project_key,service,grant_id) VALUES($1,$2,$3,$4,$5) ON CONFLICT(publisher_identity_id,team_id,project_key,service) DO UPDATE SET grant_id=EXCLUDED.grant_id`, publisher, s.TeamID, s.ProjectKey, s.Service, g.ID)
	return err
}
