package state

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

type RealizeLocalProjectServiceRequest struct {
	TeamID, ProjectKey, SourceFingerprint, Service, WorktreeKey, ActorID string
	WorktreeLabel                                                        string
	DNSAutomation                                                        bool
	Configuration                                                        ProjectServiceConfiguration
	Now                                                                  time.Time
}

type LocalProjectService struct {
	Service     string           `json:"service"`
	WorktreeKey string           `json:"worktree_key"`
	ServiceID   string           `json:"service_id"`
	Hostname    string           `json:"hostname,omitempty"`
	Metadata    *ServiceMetadata `json:"metadata,omitempty"`
}

type GetLocalProjectServiceRequest struct {
	TeamID, ProjectKey, SourceFingerprint, Service, WorktreeKey, ActorID string
	Now                                                                  time.Time
}

func validLocalProjectServiceScope(project, source, service, worktree string) bool {
	return naming.ValidProjectKey(project) && fingerprintPattern.MatchString(source) && serviceName.MatchString(service) && len(worktree) >= 1 && len(worktree) <= 128 && !strings.ContainsAny(worktree, "\x00\r\n")
}

// visitor lookup reads the recorded ID, never saved names or declarations. the
// read-only snapshot keeps provenance, live access and safe metadata consistent.
func (d *Database) GetLocalProjectService(ctx context.Context, r GetLocalProjectServiceRequest) (result LocalProjectService, retErr error) {
	if !validLocalProjectServiceScope(r.ProjectKey, r.SourceFingerprint, r.Service, r.WorktreeKey) {
		return result, ErrProjectConfigurationInvalid
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "get local project service", &retErr)()
	row, err := controlstatedb.New(tx).GetLocalProjectService(ctx, controlstatedb.GetLocalProjectServiceParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey, Service: r.Service, WorktreeKey: r.WorktreeKey})
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if _, _, err = privateVisitorAccess(ctx, tx, row.ControlService.ID, r.ActorID, r.Now); err != nil {
		return result, err
	}
	// report source collisions only after authorizing the exact bound resource.
	if row.SourceFingerprint != r.SourceFingerprint {
		return result, ErrProjectSourceConflict
	}
	if err = checkLocalProjectSource(ctx, tx, r.TeamID, r.ProjectKey, r.SourceFingerprint); err != nil {
		return result, err
	}
	var conflict bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.applied_projects WHERE team_id=$1 AND project_key=$2 AND source_fingerprint<>$3)`, r.TeamID, r.ProjectKey, r.SourceFingerprint).Scan(&conflict); err != nil {
		return result, err
	}
	if conflict {
		return result, ErrProjectSourceConflict
	}
	m, err := checkedServiceMetadata(row.ControlService)
	if err != nil {
		return result, err
	}
	m.TLS = nil
	result = LocalProjectService{Service: r.Service, WorktreeKey: r.WorktreeKey, ServiceID: row.ControlService.ID, Hostname: row.ControlService.CertificateHostname, Metadata: &m}
	return result, tx.Commit(ctx)
}

func localProjectServiceName(r RealizeLocalProjectServiceRequest, name string) string {
	digest := sha256.Sum256([]byte(r.TeamID + "\x00" + r.ProjectKey + "\x00" + r.SourceFingerprint + "\x00" + r.Service + "\x00" + r.WorktreeKey))
	return fmt.Sprintf("%.20s-%x", name, digest[:5])
}

func (d *Database) updateLocalService(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, row controlstatedb.ControlService, s ProjectServiceConfiguration, now time.Time) error {
	trust, err := appliedServiceTargetTrust(s.TargetTLS)
	if err != nil {
		return err
	}
	saved, err := checkedServiceMetadata(row)
	if err != nil {
		return err
	}
	if !serviceMetadataMatches(saved, ServiceMetadata{Protocol: s.Protocol, TLS: trust}) {
		if err := closeServiceRuns(ctx, tx, row.ID, now); err != nil {
			return err
		}
	}
	return d.updateAppliedService(ctx, tx, q, row.ID, row.NameScope, s, false, now)
}

func checkLocalProjectSource(ctx context.Context, tx pgx.Tx, team, project, source string) error {
	var conflict bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.local_project_services WHERE team_id=$1 AND project_key=$2 AND source_fingerprint<>$3)`, team, project, source).Scan(&conflict); err != nil {
		return err
	}
	if conflict {
		return ErrProjectSourceConflict
	}
	return nil
}

// realization owns only this worktree's service. it neither evaluates nor applies
// remote declarations. service IDs are allocated here, never supplied or adopted.
func (d *Database) RealizeLocalProjectService(ctx context.Context, r RealizeLocalProjectServiceRequest) (result LocalProjectService, retErr error) {
	if !validLocalProjectServiceScope(r.ProjectKey, r.SourceFingerprint, r.Service, r.WorktreeKey) {
		return result, ErrProjectConfigurationInvalid
	}
	if err := (ServicePlacement{WorktreeKey: r.WorktreeKey, WorktreeLabel: r.WorktreeLabel, DomainID: r.Configuration.DomainID}).Validate(); err != nil {
		return result, err
	}
	if r.Configuration.HTTP != nil && r.Configuration.HTTP.Access != nil && r.Configuration.HTTP.Access.IP != nil && len(r.Configuration.HTTP.Access.IP) == 0 {
		return result, ErrProjectConfigurationInvalid
	}
	data, err := json.Marshal(r.Configuration)
	if err != nil || len(data) > 512<<10 {
		return result, ErrProjectConfigurationInvalid
	}
	var s ProjectServiceConfiguration
	if err = json.Unmarshal(data, &s); err != nil {
		return result, err
	}
	// realization validates one binding. only the actual project can validate
	// cross-service destinations; never invent neighboring declarations here.
	if err = normalizeAppliedProjectService(r.Service, &s, localProjectConfiguration); err != nil {
		return result, err
	}
	s = localServiceDeclaration(s)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "realize local project service", &retErr)()
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, r.TeamID); err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	member, err := serviceMembershipForActor(ctx, tx, r.TeamID, r.ActorID, time.Now())
	if err != nil {
		return result, err
	}
	if !member.administrator() {
		// native local identities describe one canonical project directory, not
		// the portable Git source used by apply. membership alone must not claim
		// a team project's declarations or another implementer's local project.
		if r.ProjectKey != "local-"+r.SourceFingerprint[:48] {
			return result, ErrServiceAccess
		}
		var foreign bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.local_project_services
			WHERE team_id=$1 AND project_key=$2 AND created_by_identity_id<>$3)`,
			r.TeamID, r.ProjectKey, r.ActorID).Scan(&foreign); err != nil {
			return result, err
		}
		if foreign {
			return result, ErrServiceAccess
		}
	}
	if err = checkLocalProjectSource(ctx, tx, r.TeamID, r.ProjectKey, r.SourceFingerprint); err != nil {
		return result, err
	}
	project, err := q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	if err == nil {
		// saved desired intent stays manager-owned, including a deliberately
		// colliding local key. realization never grants apply/config access.
		if !member.administrator() {
			return result, ErrServiceAccess
		}
		if project.SourceFingerprint != r.SourceFingerprint {
			return result, ErrProjectSourceConflict
		}
		applied, e := d.openAppliedProject(project, "local")
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return result, e
		}
		if e == nil && !reflect.DeepEqual(applied.Services[r.Service], s) {
			return result, ErrProjectConfigurationStale
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	entry := controlstatedb.ControlAppliedProjectService{TeamID: r.TeamID, ProjectKey: r.ProjectKey, Service: r.Service}
	var oldGrant, creator string
	err = tx.QueryRow(ctx, `SELECT service_id,COALESCE(visitor_grant_id,''),created_by_identity_id FROM control.local_project_services WHERE team_id=$1 AND project_key=$2 AND service=$3 AND worktree_key=$4 FOR UPDATE`, r.TeamID, r.ProjectKey, r.Service, r.WorktreeKey).Scan(&entry.ServiceID, &oldGrant, &creator)
	found := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	if found && creator != r.ActorID {
		return result, ErrServiceAccess
	}
	if found {
		previous, e := q.LockService(ctx, entry.ServiceID.String)
		if e != nil {
			return result, e
		}
		if !member.administrator() {
			owner, e := storedServiceSourceOwner(ctx, tx, previous, previous.DeletedAt.Valid)
			if e != nil {
				return result, e
			}
			if !owner.local || owner.scope != NamespaceScopeMember || owner.membership != member.id {
				return result, ErrServiceAccess
			}
		}
		if previous.DeletedAt.Valid {
			// only runtime deletion of an ephemeral service releases this exact
			// source/worktree binding. a saved deleted service cannot be adopted.
			if !previous.Ephemeral {
				return result, ErrServiceAccess
			}
			if e = reconcileLocalVisitorGrant(ctx, tx, entry, r.WorktreeKey, r.ActorID, oldGrant, false, r.Now); e != nil {
				return result, e
			}
			if _, e = tx.Exec(ctx, `DELETE FROM control.local_project_services WHERE team_id=$1 AND project_key=$2 AND service=$3 AND worktree_key=$4`, r.TeamID, r.ProjectKey, r.Service, r.WorktreeKey); e != nil {
				return result, e
			}
			entry.ServiceID = nullableText("")
			found, oldGrant = false, ""
		}
	}
	result = LocalProjectService{Service: r.Service, WorktreeKey: r.WorktreeKey}
	local := s
	local.Name = localProjectServiceName(r, s.Name)
	if !found {
		id, e := d.createAppliedService(ctx, tx, q, ApplyProjectConfigurationRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, Now: r.Now}, r.Service, "local/"+r.ProjectKey+"/"+r.WorktreeKey, local, false)
		if e != nil {
			return result, e
		}
		entry.ServiceID = text(id)
	} else {
		row, e := q.LockService(ctx, entry.ServiceID.String)
		if e != nil {
			return result, e
		}
		if e = d.updateLocalService(ctx, tx, q, row, local, r.Now); e != nil {
			return result, e
		}
	}
	if err = d.ensureLocalServiceEndpoint(ctx, tx, entry.ServiceID.String, r.ActorID, s.Name, ServicePlacement{DomainID: s.DomainID, Hostname: s.Hostname, WorktreeKey: localPlacementKey(r.WorktreeKey), WorktreeLabel: r.WorktreeLabel, SourceKey: r.ProjectKey + "/" + r.SourceFingerprint + "/" + r.WorktreeKey + "/" + r.Service, DNSAutomation: r.DNSAutomation}, projectServicePublic(s), r.Now); err != nil {
		return result, err
	}
	row, err := q.LockService(ctx, entry.ServiceID.String)
	if err != nil {
		return result, err
	}
	m, err := checkedServiceMetadata(row)
	if err != nil {
		return result, err
	}
	result.Metadata, result.ServiceID, result.Hostname = &m, row.ID, row.CertificateHostname
	if !found {
		_, err = tx.Exec(ctx, `INSERT INTO control.local_project_services(team_id,project_key,source_fingerprint,service,worktree_key,service_id,created_by_identity_id) VALUES($1,$2,$3,$4,$5,$6,$7)`, r.TeamID, r.ProjectKey, r.SourceFingerprint, r.Service, r.WorktreeKey, entry.ServiceID, r.ActorID)
		if err != nil {
			return result, projectConstraintError(err)
		}
	}
	if err = d.saveServiceConfiguration(ctx, tx, entry.ServiceID.String, s); err != nil {
		return result, err
	}
	if err = reconcileLocalVisitorGrant(ctx, tx, entry, r.WorktreeKey, r.ActorID, oldGrant, s.Access != nil && s.Access.Team, r.Now); err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

// only local project bindings use this projection. standalone saved services and
// encrypted remote deployments retain targets that their publishers must resolve.
func localServiceDeclaration(value ProjectServiceConfiguration) ProjectServiceConfiguration {
	value.Target, value.TargetDiscovery = "app", nil
	value.HTTP = config.HTTPRequestPolicy(value.HTTP)
	return value
}

func reconcileLocalVisitorGrant(ctx context.Context, tx pgx.Tx, entry controlstatedb.ControlAppliedProjectService, worktree, actor, grant string, enabled bool, now time.Time) error {
	id, err := reconcileProjectVisitorGrant(ctx, tx, entry, actor, grant, enabled, now)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE control.local_project_services SET visitor_grant_id=$5 WHERE team_id=$1 AND project_key=$2 AND service=$3 AND worktree_key=$4`, entry.TeamID, entry.ProjectKey, entry.Service, worktree, nullableText(id))
	return err
}

// apply reconciles only already-proven local IDs. deferred listeners are never
// allocated here, and removing access revokes only the configuration-owned grant.
func (d *Database) reconcileProjectLocalRealizations(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, r ApplyProjectConfigurationRequest, current ProjectConfiguration) error {
	rows, err := tx.Query(ctx, `SELECT DISTINCT service FROM control.local_project_services WHERE team_id=$1 AND project_key=$2 ORDER BY service`, r.TeamID, r.ProjectKey)
	if err != nil {
		return err
	}
	var keys []string
	for rows.Next() {
		var key string
		if err = rows.Scan(&key); err != nil {
			rows.Close()
			return err
		}
		keys = append(keys, key)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, key := range keys {
		var declared *ProjectServiceConfiguration
		if s, found := current.Services[key]; found {
			declared = &s
		}
		if err = d.reconcileLocalProjectServices(ctx, tx, q, r, key, declared); err != nil {
			return err
		}
	}
	return nil
}

func (d *Database) reconcileLocalProjectServices(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, r ApplyProjectConfigurationRequest, key string, s *ProjectServiceConfiguration) error {
	rows, err := tx.Query(ctx, `SELECT worktree_key,service_id,COALESCE(visitor_grant_id,'') FROM control.local_project_services WHERE team_id=$1 AND project_key=$2 AND service=$3 ORDER BY worktree_key`, r.TeamID, r.ProjectKey, key)
	if err != nil {
		return err
	}
	type local struct {
		worktree, grant string
		entry           controlstatedb.ControlAppliedProjectService
	}
	var locals []local
	for rows.Next() {
		v := local{entry: controlstatedb.ControlAppliedProjectService{TeamID: r.TeamID, ProjectKey: r.ProjectKey, Service: key}}
		if err = rows.Scan(&v.worktree, &v.entry.ServiceID, &v.grant); err != nil {
			rows.Close()
			return err
		}
		locals = append(locals, v)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, v := range locals {
		if err = reconcileLocalVisitorGrant(ctx, tx, v.entry, v.worktree, r.ActorID, v.grant, s != nil && s.Access != nil && s.Access.Team, r.Now); err != nil {
			return err
		}
		if s == nil {
			if err = d.revokeProjectResourcePublishers(ctx, tx, q, v.entry, r.Now); err != nil {
				return err
			}
			if err = d.retireProjectResource(ctx, tx, q, v.entry, r.Now); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `DELETE FROM control.local_project_services WHERE team_id=$1 AND project_key=$2 AND service=$3 AND worktree_key=$4`, r.TeamID, r.ProjectKey, key, v.worktree); err != nil {
				return err
			}
			continue
		}
		row, e := q.LockService(ctx, v.entry.ServiceID.String)
		if e != nil {
			return e
		}
		if s.Hostname != "" && s.Hostname != row.CertificateHostname || s.DomainID != "" && s.DomainID != row.DomainID.String {
			return ErrServiceConflict
		}
		local := *s
		local.Name = localProjectServiceName(RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: key, WorktreeKey: v.worktree}, s.Name)
		if err = d.updateLocalService(ctx, tx, q, row, local, r.Now); err != nil {
			return err
		}
		if err = d.setLocalServiceExposure(ctx, tx, row.ID, projectServicePublic(*s), r.Now); err != nil {
			return err
		}
		if err = d.saveServiceConfiguration(ctx, tx, row.ID, *s); err != nil {
			return err
		}
	}
	return nil
}

type ProjectPublicService struct {
	Service   string `json:"service"`
	ServiceID string `json:"service_id"`
	Port      int    `json:"port"`
	Hostname  string `json:"hostname"`
}
type ProjectPublicMetadata struct {
	SourceFingerprint string                 `json:"source_fingerprint"`
	Services          []ProjectPublicService `json:"services"`
}

// browser preparation receives only immutable public service IDs and hostnames.
// visitor permission never authorizes reading targets, trust, grants or config.
func (d *Database) GetProjectPublicMetadata(ctx context.Context, team, project, actor string, now time.Time) (result ProjectPublicMetadata, retErr error) {
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "get project public metadata", &retErr)()
	managerErr := serviceManager(ctx, tx, team, actor)
	if managerErr != nil && !errors.Is(managerErr, ErrServiceAccess) {
		return result, managerErr
	}
	manager := managerErr == nil
	err = tx.QueryRow(ctx, `SELECT source_fingerprint FROM control.applied_projects WHERE team_id=$1 AND project_key=$2
	    UNION SELECT source_fingerprint FROM control.local_project_services WHERE team_id=$1 AND project_key=$2 LIMIT 1`, team, project).Scan(&result.SourceFingerprint)
	if err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	rows, err := tx.Query(ctx, `SELECT a.service,s.id,s.certificate_hostname,s.service_port FROM (
	      SELECT team_id,project_key,service,service_id FROM control.applied_project_services
	      UNION SELECT team_id,project_key,service,service_id FROM control.local_project_services
	    ) a JOIN control.services s ON s.id=a.service_id
	    WHERE a.team_id=$1 AND a.project_key=$2 AND s.enabled AND s.deleted_at IS NULL AND s.public AND s.protocol='http'
	    ORDER BY 1,2`, team, project)
	if err != nil {
		return result, err
	}
	result.Services = []ProjectPublicService{}
	for rows.Next() {
		var s ProjectPublicService
		if err = rows.Scan(&s.Service, &s.ServiceID, &s.Hostname, &s.Port); err != nil {
			rows.Close()
			return result, err
		}
		result.Services = append(result.Services, s)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	if !manager {
		visible := result.Services[:0]
		for _, service := range result.Services {
			if service.ServiceID != "" {
				if _, _, err := privateVisitorAccess(ctx, tx, service.ServiceID, actor, now); errors.Is(err, ErrServiceAccess) {
					continue
				} else if err != nil {
					return result, err
				}
			}
			visible = append(visible, service)
		}
		result.Services = visible
	}
	if !manager && len(result.Services) == 0 {
		return ProjectPublicMetadata{}, ErrServiceAccess
	}
	return result, tx.Commit(ctx)
}
