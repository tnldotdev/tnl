package state

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

type RealizeLocalProjectServiceRequest struct {
	TeamID, ProjectKey, SourceFingerprint, Service, WorktreeKey, ActorID string
	PublicURLID                                                          string
	DomainID, WorktreeLabel                                              string
	DNSAutomation                                                        bool
	Configuration                                                        ProjectServiceConfiguration
	Now                                                                  time.Time
}

type LocalProjectService struct {
	Service     string           `json:"service"`
	WorktreeKey string           `json:"worktree_key"`
	Kind        string           `json:"service_kind"`
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
	result = LocalProjectService{Service: r.Service, WorktreeKey: r.WorktreeKey, Kind: "service", ServiceID: row.ControlService.ID, Metadata: &m}
	return result, tx.Commit(ctx)
}

func localProjectPrivateName(r RealizeLocalProjectServiceRequest, name string) string {
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
		if _, err := tx.Exec(ctx, `UPDATE control.service_runs SET state='closed',closed_at=$2 WHERE service_id=$1 AND closed_at IS NULL`, row.ID, now); err != nil {
			return err
		}
	}
	return d.updateAppliedService(ctx, tx, q, row.ID, row.NameScope, s, now)
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

// realization owns only this worktree's local resource. it neither evaluates nor
// applies remote declarations. private IDs are allocated here, never found by name.
// public IDs must be exact caller-owned app URLs allocated by the normal runtime.
func (d *Database) RealizeLocalProjectService(ctx context.Context, r RealizeLocalProjectServiceRequest) (result LocalProjectService, retErr error) {
	if !validLocalProjectServiceScope(r.ProjectKey, r.SourceFingerprint, r.Service, r.WorktreeKey) {
		return result, ErrProjectConfigurationInvalid
	}
	services := map[string]ProjectServiceConfiguration{r.Service: r.Configuration}
	if err := (ServicePlacement{WorktreeKey: r.WorktreeKey, WorktreeLabel: r.WorktreeLabel, DomainID: r.DomainID}).Validate(); err != nil {
		return result, err
	}
	// this endpoint realizes one resource, not the path destinations. include
	// inert declarations only so shared path-reference validation remains exact.
	if r.Configuration.HTTP != nil {
		for _, mount := range r.Configuration.HTTP.Paths {
			if mount.Service != r.Service {
				services[mount.Service] = ProjectServiceConfiguration{Protocol: "http", Target: "app"}
			}
		}
	}
	c, _, err := NormalizeProjectConfiguration(ProjectConfiguration{Services: services})
	if err != nil {
		return result, err
	}
	s := c.Services[r.Service]
	if s.PublisherGroup != "local" || (s.PublicURL != nil) != (r.PublicURLID != "") {
		return result, ErrProjectConfigurationInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "realize local project service", &retErr)()
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, r.TeamID); err != nil {
		return result, publisherLookupError(err, ErrServiceAccess)
	}
	if err = serviceManager(ctx, tx, r.TeamID, r.ActorID); err != nil {
		return result, err
	}
	if err = checkLocalProjectSource(ctx, tx, r.TeamID, r.ProjectKey, r.SourceFingerprint); err != nil {
		return result, err
	}
	project, err := q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
	if err == nil {
		if project.SourceFingerprint != r.SourceFingerprint {
			return result, ErrProjectSourceConflict
		}
		applied, e := d.openAppliedProject(project)
		if e != nil {
			return result, e
		}
		if !reflect.DeepEqual(applied.Services[r.Service], s) {
			return result, ErrProjectConfigurationStale
		}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	entry := controlstatedb.ControlAppliedProjectService{TeamID: r.TeamID, ProjectKey: r.ProjectKey, Service: r.Service}
	var oldGrant, creator string
	err = tx.QueryRow(ctx, `SELECT service_id,public_url_id,COALESCE(visitor_grant_id,''),created_by_identity_id FROM control.local_project_services WHERE team_id=$1 AND project_key=$2 AND service=$3 AND worktree_key=$4 FOR UPDATE`, r.TeamID, r.ProjectKey, r.Service, r.WorktreeKey).Scan(&entry.ServiceID, &entry.PublicURLID, &oldGrant, &creator)
	found := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	if found && creator != r.ActorID {
		return result, ErrServiceAccess
	}
	if found && (s.PublicURL == nil) != entry.ServiceID.Valid {
		return result, ErrProjectManaged
	}
	if found && s.PublicURL != nil && entry.PublicURLID.String != r.PublicURLID {
		previous, e := q.LockPublicURLForRun(ctx, entry.PublicURLID.String)
		if e != nil {
			return result, e
		}
		// automatic ephemeral expiry is runtime lifecycle, not a definition edit.
		// only a deleted ephemeral resource may release this provenance binding.
		if !previous.Ephemeral || previous.LifecycleState != "deleted" {
			return result, ErrProjectManaged
		}
		if e = reconcileLocalVisitorGrant(ctx, tx, entry, r.WorktreeKey, r.ActorID, oldGrant, false, r.Now); e != nil {
			return result, e
		}
		if _, e = tx.Exec(ctx, `DELETE FROM control.local_project_services WHERE team_id=$1 AND project_key=$2 AND service=$3 AND worktree_key=$4`, r.TeamID, r.ProjectKey, r.Service, r.WorktreeKey); e != nil {
			return result, e
		}
		entry.PublicURLID = nullableText("")
		found, oldGrant = false, ""
	}
	result = LocalProjectService{Service: r.Service, WorktreeKey: r.WorktreeKey, Kind: "service"}
	if s.PublicURL == nil {
		if !found {
			// scope saved names too, so two worktrees cannot share a private run.
			local := s
			local.Name = localProjectPrivateName(r, s.Name)
			id, e := d.createAppliedService(ctx, tx, q, ApplyProjectConfigurationRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, Now: r.Now}, r.Service, "local/"+r.ProjectKey+"/"+r.WorktreeKey, local)
			if e != nil {
				return result, e
			}
			entry.ServiceID = text(id)
		} else {
			row, e := q.LockService(ctx, entry.ServiceID.String)
			if e != nil {
				return result, e
			}
			if row.DeletedAt.Valid {
				return result, ErrServiceAccess
			}
			local := s
			local.Name = localProjectPrivateName(r, s.Name)
			if e = d.updateLocalService(ctx, tx, q, row, local, r.Now); e != nil {
				return result, e
			}
		}
		row, e := q.LockService(ctx, entry.ServiceID.String)
		if e != nil {
			return result, e
		}
		if e = d.ensureLocalServiceEndpoint(ctx, tx, row.ID, r.ActorID, s.Name, ServicePlacement{DomainID: r.DomainID, WorktreeKey: localPlacementKey(r.WorktreeKey), WorktreeLabel: r.WorktreeLabel, SourceKey: r.ProjectKey + "/" + r.SourceFingerprint + "/" + r.WorktreeKey + "/" + r.Service, DNSAutomation: r.DNSAutomation}, r.Now); e != nil {
			return result, e
		}
		row, e = q.LockService(ctx, row.ID)
		if e != nil {
			return result, e
		}
		m, e := checkedServiceMetadata(row)
		if e != nil {
			return result, e
		}
		result.Metadata = &m
		result.ServiceID = row.ID
	} else {
		u, e := q.LockPublicURLForRun(ctx, r.PublicURLID)
		if e != nil {
			return result, publisherLookupError(e, ErrPublicURLAccess)
		}
		if u.TeamID != r.TeamID || u.CreatedByIdentityID != r.ActorID || u.Purpose != "app" || u.PublisherPool || u.LifecycleState != "enabled" {
			return result, ErrPublicURLAccess
		}
		if e = d.authorizeLocalProjectPublicURL(ctx, q, u, r.ActorID); e != nil {
			return result, e
		}
		if s.PublicURL.Hostname != "" && s.PublicURL.Hostname != u.CanonicalHostname || s.PublicURL.DomainID != "" && s.PublicURL.DomainID != u.DomainID || s.PublicURL.Ephemeral != u.Ephemeral {
			return result, ErrProjectConfigurationInvalid
		}
		if !found {
			if e = rejectProjectManagedDefinition(ctx, tx, u.ID); e != nil {
				return result, e
			}
		}
		entry.PublicURLID = text(u.ID)
		result.Kind, result.ServiceID, result.Hostname = "public_url", u.ID, u.CanonicalHostname
	}
	if !found {
		_, err = tx.Exec(ctx, `INSERT INTO control.local_project_services(team_id,project_key,source_fingerprint,service,worktree_key,service_id,public_url_id,created_by_identity_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, r.TeamID, r.ProjectKey, r.SourceFingerprint, r.Service, r.WorktreeKey, entry.ServiceID, entry.PublicURLID, r.ActorID)
		if err != nil {
			return result, projectConstraintError(err)
		}
	}
	if err = reconcileLocalVisitorGrant(ctx, tx, entry, r.WorktreeKey, r.ActorID, oldGrant, s.Access != nil && s.Access.Team, r.Now); err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

func (d *Database) authorizeLocalProjectPublicURL(ctx context.Context, q *controlstatedb.Queries, u controlstatedb.ControlPublicUrl, actor string) error {
	creation, err := q.GetPublicURLCreationContext(ctx, controlstatedb.GetPublicURLCreationContextParams{IdentityID: actor, DomainID: u.DomainID, TeamID: u.TeamID})
	if err != nil {
		return publisherLookupError(err, ErrPublicURLAccess)
	}
	switch u.PublicURLScope {
	case "member":
		if !u.MembershipID.Valid || u.MembershipID.String != creation.ActorMembershipID {
			return ErrPublicURLAccess
		}
	case "shared":
		_, direct := naming.PublicURLNamespace(naming.NamespaceFacts{Domain: creation.CanonicalDomain, Managed: creation.DomainKind == "managed", Mode: d.managedURLMode, Personal: creation.TeamKind == "personal", TeamName: creation.TeamDisplayName, MemberSlug: creation.ActorMemberSlug, ManagedLabel: creation.ActorManagedLabel})
		if creation.TeamKind != "personal" || creation.TeamCreatorIdentityID != actor || !direct || u.MembershipID.Valid || creation.ActorRole != "owner" && creation.ActorRole != "admin" {
			return ErrPublicURLAccess
		}
	default:
		return ErrPublicURLAccess
	}
	labels, err := q.ListTeamNamespaceLabels(ctx, u.TeamID)
	if err != nil {
		return err
	}
	return authorizeRouteCreation(CreatePublicURLRequest{TeamID: u.TeamID, DomainID: u.DomainID, ActingIdentityID: actor, MembershipID: u.MembershipID.String, CanonicalHostname: u.CanonicalHostname, PublicURLScope: PublicURLScope(u.PublicURLScope), ManagedURLMode: d.managedURLMode}, creation, labels)
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
func (d *Database) reconcileProjectLocalRealizations(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, r ApplyProjectConfigurationRequest, old, current ProjectConfiguration) error {
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
		if s, found := current.Services[key]; found && s.PublisherGroup == "local" {
			declared = &s
		}
		previous, hadPrevious := old.Services[key]
		reset := hadPrevious && declared != nil && previous.PublicURL != nil && declared.PublicURL != nil && (!sameAppliedResource(previous, *declared) || previous.Name != declared.Name || previous.PublicURL.Ephemeral != declared.PublicURL.Ephemeral)
		if err = d.reconcileLocalProjectServices(ctx, tx, q, r, key, declared, !reflect.DeepEqual(previous.PublicURL, current.Services[key].PublicURL), reset); err != nil {
			return err
		}
	}
	return nil
}

func (d *Database) reconcileLocalProjectServices(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, r ApplyProjectConfigurationRequest, key string, s *ProjectServiceConfiguration, publicChanged, reset bool) error {
	rows, err := tx.Query(ctx, `SELECT worktree_key,service_id,public_url_id,COALESCE(visitor_grant_id,'') FROM control.local_project_services WHERE team_id=$1 AND project_key=$2 AND service=$3 ORDER BY worktree_key`, r.TeamID, r.ProjectKey, key)
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
		if err = rows.Scan(&v.worktree, &v.entry.ServiceID, &v.entry.PublicURLID, &v.grant); err != nil {
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
		compatible := !reset && s != nil && (s.PublicURL == nil) == v.entry.ServiceID.Valid
		if err = reconcileLocalVisitorGrant(ctx, tx, v.entry, v.worktree, r.ActorID, v.grant, compatible && s.Access != nil && s.Access.Team, r.Now); err != nil {
			return err
		}
		if !compatible {
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
		if v.entry.PublicURLID.Valid && publicChanged {
			if err = d.reconcileAppliedPublicSettings(ctx, tx, q, v.entry.PublicURLID.String, s.PublicURL, r.Now); err != nil {
				return err
			}
		}
		if v.entry.ServiceID.Valid {
			row, e := q.LockService(ctx, v.entry.ServiceID.String)
			if e != nil {
				return e
			}
			local := *s
			local.Name = localProjectPrivateName(RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: key, WorktreeKey: v.worktree}, s.Name)
			if err = d.updateLocalService(ctx, tx, q, row, local, r.Now); err != nil {
				return err
			}
		}
	}
	return nil
}

type ProjectPublicService struct {
	Service     string `json:"service"`
	PublicURLID string `json:"public_url_id,omitempty"`
	ServiceID   string `json:"service_id,omitempty"`
	Port        int    `json:"port"`
	Hostname    string `json:"hostname"`
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
		return result, publisherLookupError(err, ErrPublicURLNotFound)
	}
	rows, err := tx.Query(ctx, `WITH public_services AS (
	    SELECT service,public_url_id FROM control.applied_project_services WHERE team_id=$1 AND project_key=$2
	    UNION SELECT service,public_url_id FROM control.local_project_services WHERE team_id=$1 AND project_key=$2)
	    SELECT s.service,u.id,''::text,u.canonical_hostname,443 FROM public_services s JOIN control.public_urls u ON u.id=s.public_url_id AND u.lifecycle_state='enabled'
	    WHERE $5 OR EXISTS(SELECT 1 FROM control.visitor_identity_permission('public_url',u.id,$3,$6,'',$4))
	    UNION ALL SELECT a.service,''::text,s.id,s.certificate_hostname,s.service_port FROM control.applied_project_services a JOIN control.services s ON s.id=a.service_id
	    WHERE a.team_id=$1 AND a.project_key=$2 AND s.enabled AND s.deleted_at IS NULL AND s.public AND s.protocol='http'
	    ORDER BY 1,2,3`, team, project, actor, now, manager, companySessionID(ctx, actor))
	if err != nil {
		return result, err
	}
	result.Services = []ProjectPublicService{}
	for rows.Next() {
		var s ProjectPublicService
		if err = rows.Scan(&s.Service, &s.PublicURLID, &s.ServiceID, &s.Hostname, &s.Port); err != nil {
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
		return ProjectPublicMetadata{}, ErrPublicURLAccess
	}
	return result, tx.Commit(ctx)
}
