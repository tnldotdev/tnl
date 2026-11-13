package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

var (
	ErrDeploymentNotFound = errors.New("deployment not found")
	ErrDeploymentStale    = errors.New("deployment changed")
)

type DeploymentService struct {
	ID            string           `json:"id"`
	Protocol      string           `json:"protocol"`
	TrustRevision int64            `json:"trust_revision"`
	Endpoint      *ServiceEndpoint `json:"endpoint,omitempty"`
}

type Deployment struct {
	ID         string                            `json:"id"`
	TeamID     string                            `json:"team_id"`
	ProjectKey string                            `json:"project_key"`
	Name       string                            `json:"name"`
	Revision   int64                             `json:"revision"`
	Targets    map[string]DeploymentTargetStatus `json:"targets"`
	Services   map[string]DeploymentService      `json:"services"`
}

type DeploymentScope struct {
	TeamID, ProjectKey, ActorID string
	AccessToken                 string `json:"-"`
}

type CreateDeploymentRequest struct {
	DeploymentScope
	Name, IdempotencyKey string
	Targets              map[string]DeploymentTarget
	DNSAutomation        bool
	Now                  time.Time
}

type UpdateDeploymentRequest struct {
	DeploymentScope
	Selector         string
	ExpectedRevision int64
	Targets          map[string]DeploymentTarget
	Now              time.Time
}

// every operation takes the same team guard as apply, then checks current
// authority. a name, request key, or previous successful read is not permission.
func lockDeploymentManager(ctx context.Context, tx pgx.Tx, scope DeploymentScope) (controlstatedb.ControlAppliedProject, error) {
	q := controlstatedb.New(tx)
	if scope.AccessToken != "" {
		return controlstatedb.ControlAppliedProject{}, ErrDeploymentAccess
	}
	// website service-access proofs are not project-management credentials.
	if _, signed := serviceActor(ctx); signed {
		return controlstatedb.ControlAppliedProject{}, ErrServiceAccess
	}
	if !naming.ValidProjectKey(scope.ProjectKey) {
		return controlstatedb.ControlAppliedProject{}, ErrProjectConfigurationInvalid
	}
	if _, err := q.LockLocalTeamForMutation(ctx, scope.TeamID); err != nil {
		return controlstatedb.ControlAppliedProject{}, publisherLookupError(err, ErrServiceAccess)
	}
	if err := serviceManager(ctx, tx, scope.TeamID, scope.ActorID); err != nil {
		return controlstatedb.ControlAppliedProject{}, err
	}
	row, err := q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: scope.TeamID, ProjectKey: scope.ProjectKey})
	return row, publisherLookupError(err, ErrDeploymentNotFound)
}

func commitDeployment(ctx context.Context, tx pgx.Tx, scope DeploymentScope) error {
	// locks may have waited beyond a session's deadline or an identity change.
	if err := serviceManager(ctx, tx, scope.TeamID, scope.ActorID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (d *Database) CreateDeployment(ctx context.Context, r CreateDeploymentRequest) (result Deployment, retErr error) {
	if !naming.ValidServiceName(r.Name) || r.Name == "local" || !validIdempotencyKey(r.IdempotencyKey) || len(r.Targets) == 0 || len(r.Targets) > 128 {
		return result, ErrProjectConfigurationInvalid
	}
	data, err := json.Marshal(struct {
		Name    string                      `json:"name"`
		Targets map[string]DeploymentTarget `json:"targets"`
	}{r.Name, r.Targets})
	if err != nil || len(data) > 512<<10 {
		return result, ErrProjectConfigurationInvalid
	}
	digest := sha256.Sum256(data)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "create deployment", &retErr)()
	access, project, err := d.lockDeploymentAccess(ctx, tx, r.DeploymentScope, r.Now)
	if err != nil {
		return result, err
	}
	r.ActorID = access.actorID
	if access.grantID != "" && !access.allDeployments {
		return result, ErrDeploymentAccess
	}
	if err = access.servicesAllowed(sortedProjectKeys(r.Targets)); err != nil {
		return result, err
	}
	var id string
	var savedDigest []byte
	var deleted bool
	err = tx.QueryRow(ctx, `SELECT id,create_request_digest,deleted_at IS NOT NULL FROM control.project_publisher_groups
		WHERE team_id=$1 AND project_key=$2 AND create_principal_id=$3 AND create_idempotency_key=$4`,
		r.TeamID, r.ProjectKey, access.principalID, r.IdempotencyKey).Scan(&id, &savedDigest, &deleted)
	if err == nil {
		if deleted || !bytes.Equal(digest[:], savedDigest) {
			return result, ErrServiceConflict
		}
		row, err := controlstatedb.New(tx).LockProjectPublisherGroup(ctx, id)
		if err != nil {
			return result, err
		}
		result, err = d.deploymentStatus(ctx, tx, row, access)
		if err != nil {
			return result, err
		}
		return result, d.commitDeploymentAccess(ctx, tx, access)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	if err = d.lockDeploymentMutation(ctx, tx, access); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	snapshot, err := deploymentTargets(ctx, q, r.DeploymentScope, r.Name, r.Targets)
	if err != nil {
		return result, err
	}
	c := ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{r.Name: {}}, Services: snapshot.Services}
	c, err = resolveManagedGroupDomains(ctx, tx, r.TeamID, r.ProjectKey, c)
	if err != nil {
		return result, err
	}
	id, err = opaqueid.New("pgrp_")
	if err != nil {
		return result, err
	}
	if err = access.setAuditActor(ctx, tx); err != nil {
		return result, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO control.project_publisher_groups(id,team_id,project_key,name,create_principal_id,create_idempotency_key,create_request_digest)
		VALUES($1,$2,$3,$4,$5,$6,$7)`, id, r.TeamID, r.ProjectKey, r.Name, access.principalID, r.IdempotencyKey, digest[:])
	if err != nil {
		return result, projectConstraintError(err)
	}
	apply := ApplyProjectConfigurationRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ProjectLabel: project.ProjectLabel, ActorID: r.ActorID, Now: r.Now, DNSAutomation: r.DNSAutomation}
	if err = d.ensureGroupNamespace(ctx, tx, apply, id, r.Name, c.PublisherGroups[r.Name]); err != nil {
		return result, err
	}
	for _, name := range sortedProjectKeys(c.Services) {
		serviceID, err := d.createAppliedService(ctx, tx, q, apply, name, id, c.Services[name])
		if err != nil {
			return result, err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO control.applied_project_services(team_id,project_key,service,group_id,service_id,desired_revision) VALUES($1,$2,$3,$4,$5,1)`, r.TeamID, r.ProjectKey, name, id, serviceID); err != nil {
			return result, err
		}
		if err = d.ensureServiceEndpoint(ctx, tx, serviceID, id, r.DNSAutomation, r.Now); err != nil {
			return result, err
		}
	}
	if err = d.saveDeploymentConfiguration(ctx, tx, id, r.Name, c); err != nil {
		return result, err
	}
	if err = access.recordUpdate(ctx, tx, id, "deployment/create/"+id, r.Now); err != nil {
		return result, err
	}
	row, err := q.LockProjectPublisherGroup(ctx, id)
	if err != nil {
		return result, err
	}
	result, err = d.deploymentStatus(ctx, tx, row, access)
	if err != nil {
		return result, err
	}
	return result, d.commitDeploymentAccess(ctx, tx, access)
}

func deploymentTargets(ctx context.Context, q *controlstatedb.Queries, scope DeploymentScope, group string, targets map[string]DeploymentTarget) (deploymentConfiguration, error) {
	result := deploymentConfiguration{Services: map[string]ProjectServiceConfiguration{}}
	declarations, err := q.ListProjectServiceDeclarations(ctx, controlstatedb.ListProjectServiceDeclarationsParams{TeamID: scope.TeamID, ProjectKey: scope.ProjectKey})
	if err != nil {
		return result, err
	}
	protocols := map[string]string{}
	for _, declaration := range declarations {
		protocols[declaration.Name] = declaration.Protocol
	}
	for _, name := range sortedProjectKeys(targets) {
		protocol := protocols[name]
		if protocol == "" {
			return result, ErrProjectConfigurationInvalid
		}
		s, err := normalizeDeploymentTarget(ctx, name, protocol, group, targets[name])
		if err != nil {
			return result, err
		}
		result.Services[name] = s
	}
	return result, nil
}

// updates replace only addresses and target trust for selected saved bindings.
// omitted services, hostname ownership, access, and HTTP policy stay unchanged.
func (d *Database) UpdateDeployment(ctx context.Context, r UpdateDeploymentRequest) (result Deployment, retErr error) {
	if r.ExpectedRevision < 1 || r.ExpectedRevision == 1<<63-1 || len(r.Targets) == 0 || len(r.Targets) > 128 {
		return result, ErrProjectConfigurationInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "update deployment", &retErr)()
	access, _, err := d.lockDeploymentAccess(ctx, tx, r.DeploymentScope, r.Now)
	if err != nil {
		return result, err
	}
	r.ActorID = access.actorID
	if err = access.servicesAllowed(sortedProjectKeys(r.Targets)); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	row, err := q.LockDeployment(ctx, controlstatedb.LockDeploymentParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey, Selector: r.Selector})
	if err != nil {
		return result, publisherLookupError(err, ErrDeploymentNotFound)
	}
	if !access.deploymentAllowed(row.ID) {
		return result, ErrDeploymentNotFound
	}
	if row.Revision != r.ExpectedRevision {
		return result, ErrDeploymentStale
	}
	snapshot, err := d.openDeploymentConfiguration(row)
	if err != nil {
		return result, err
	}
	requested, err := deploymentTargets(ctx, q, r.DeploymentScope, row.Name, r.Targets)
	if err != nil {
		return result, err
	}
	bindings, err := q.ListPublisherGroupServices(ctx, row.ID)
	if err != nil {
		return result, err
	}
	byName := map[string]controlstatedb.ControlAppliedProjectService{}
	for _, binding := range bindings {
		byName[binding.Service] = binding
	}
	for name := range requested.Services {
		if _, ok := snapshot.Services[name]; !ok || !byName[name].ServiceID.Valid {
			return result, ErrProjectConfigurationInvalid
		}
	}
	if err = access.setAuditActor(ctx, tx); err != nil {
		return result, err
	}
	if err = lockAppliedProjectPublications(ctx, tx, r.TeamID, r.ProjectKey); err != nil {
		return result, err
	}
	if err = d.lockDeploymentMutation(ctx, tx, access); err != nil {
		return result, err
	}
	for _, name := range sortedProjectKeys(requested.Services) {
		previous := snapshot.Services[name]
		next := requested.Services[name]
		previous.Target, previous.TargetTLS, previous.TargetDiscovery = next.Target, next.TargetTLS, nil
		if reflect.DeepEqual(previous, snapshot.Services[name]) {
			continue
		}
		binding := byName[name]
		if err = d.revokeAppliedServicePublishers(ctx, tx, q, binding, r.Now); err != nil {
			return result, err
		}
		if err = d.updateAppliedService(ctx, tx, q, binding.ServiceID.String, row.ID, previous, r.Now); err != nil {
			return result, err
		}
		if err = d.reconcileAppliedPublisherGrants(ctx, tx, q, binding, r.ActorID, r.Now); err != nil {
			return result, err
		}
		snapshot.Services[name] = previous
	}
	if err = d.writeDeploymentConfiguration(ctx, tx, row, snapshot); err != nil {
		return result, err
	}
	row, err = q.LockProjectPublisherGroup(ctx, row.ID)
	if err != nil {
		return result, err
	}
	if row.Revision != r.ExpectedRevision {
		if err = access.recordUpdate(ctx, tx, row.ID, "deployment/update/"+row.ConfigurationHash, r.Now); err != nil {
			return result, err
		}
	}
	result, err = d.deploymentStatus(ctx, tx, row, access)
	if err != nil {
		return result, err
	}
	return result, d.commitDeploymentAccess(ctx, tx, access)
}

func (d *Database) GetDeployment(ctx context.Context, scope DeploymentScope, selector string) (result Deployment, retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "get deployment", &retErr)()
	access, _, err := d.lockDeploymentAccess(ctx, tx, scope, time.Now())
	if err != nil {
		return result, err
	}
	row, err := controlstatedb.New(tx).LockDeployment(ctx, controlstatedb.LockDeploymentParams{TeamID: scope.TeamID, ProjectKey: scope.ProjectKey, Selector: selector})
	if err != nil {
		return result, publisherLookupError(err, ErrDeploymentNotFound)
	}
	if !access.deploymentAllowed(row.ID) {
		return result, ErrDeploymentNotFound
	}
	result, err = d.deploymentStatus(ctx, tx, row, access)
	if err != nil {
		return result, err
	}
	return result, d.commitDeploymentAccess(ctx, tx, access)
}

func (d *Database) ListDeployments(ctx context.Context, scope DeploymentScope, after string, limit int) (result []Deployment, retErr error) {
	if limit < 1 || limit > 100 || after != "" && !opaqueid.Valid(after, "pgrp_") {
		return nil, ErrProjectConfigurationInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(ctx, tx, "list deployments", &retErr)()
	access, _, err := d.lockDeploymentAccess(ctx, tx, scope, time.Now())
	if err != nil {
		return nil, err
	}
	q := controlstatedb.New(tx)
	var rows []controlstatedb.ControlProjectPublisherGroup
	if access.grantID == "" {
		rows, err = q.ListDeployments(ctx, controlstatedb.ListDeploymentsParams{TeamID: scope.TeamID, ProjectKey: scope.ProjectKey, AfterID: after, PageLimit: int32(limit)})
	} else {
		rows, err = q.ListAuthorizedDeployments(ctx, controlstatedb.ListAuthorizedDeploymentsParams{GrantID: access.grantID, AfterID: after, PageLimit: int32(limit)})
	}
	if err != nil {
		return nil, err
	}
	result = []Deployment{}
	for _, row := range rows {
		deployment, err := d.deploymentStatus(ctx, tx, row, access)
		if err != nil {
			return nil, err
		}
		result = append(result, deployment)
	}
	return result, d.commitDeploymentAccess(ctx, tx, access)
}

func (d *Database) DeleteDeployment(ctx context.Context, scope DeploymentScope, selector string, expected int64, now time.Time) (retErr error) {
	if expected < 1 {
		return ErrProjectConfigurationInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "delete deployment", &retErr)()
	access, _, err := d.lockDeploymentAccess(ctx, tx, scope, now)
	if err != nil {
		return err
	}
	scope.ActorID = access.actorID
	q := controlstatedb.New(tx)
	row, err := q.LockDeployment(ctx, controlstatedb.LockDeploymentParams{TeamID: scope.TeamID, ProjectKey: scope.ProjectKey, Selector: selector})
	if err != nil {
		return publisherLookupError(err, ErrDeploymentNotFound)
	}
	if !access.deploymentAllowed(row.ID) {
		return ErrDeploymentNotFound
	}
	if row.Revision != expected {
		return ErrDeploymentStale
	}
	bindings, err := q.ListPublisherGroupServices(ctx, row.ID)
	if err != nil {
		return err
	}
	for _, binding := range bindings {
		if err = access.servicesAllowed([]string{binding.Service}); err != nil {
			return err
		}
	}
	if err = access.setAuditActor(ctx, tx); err != nil {
		return err
	}
	if err = lockAppliedProjectPublications(ctx, tx, scope.TeamID, scope.ProjectKey); err != nil {
		return err
	}
	if err = d.lockDeploymentMutation(ctx, tx, access); err != nil {
		return err
	}
	if err = access.recordUpdate(ctx, tx, row.ID, "deployment/delete/"+row.ID, now); err != nil {
		return err
	}
	for _, binding := range bindings {
		if err = d.removeAppliedService(ctx, tx, q, binding, now); err != nil {
			return err
		}
	}
	if err = d.removePublisherGroup(ctx, tx, q, row.ID, now); err != nil {
		return err
	}
	return d.commitDeploymentAccess(ctx, tx, access)
}

func (d *Database) deploymentStatus(ctx context.Context, tx pgx.Tx, row controlstatedb.ControlProjectPublisherGroup, access deploymentAccess) (Deployment, error) {
	result := Deployment{ID: row.ID, TeamID: row.TeamID, ProjectKey: row.ProjectKey, Name: row.Name, Revision: row.Revision, Targets: map[string]DeploymentTargetStatus{}, Services: map[string]DeploymentService{}}
	snapshot, err := d.openDeploymentConfiguration(row)
	if err != nil {
		return result, err
	}
	bindings, err := controlstatedb.New(tx).ListPublisherGroupServices(ctx, row.ID)
	if err != nil {
		return result, err
	}
	for _, binding := range bindings {
		if access.servicesAllowed([]string{binding.Service}) != nil {
			continue
		}
		service, ok := snapshot.Services[binding.Service]
		if !ok || !binding.ServiceID.Valid {
			return result, ErrProjectConfigurationStale
		}
		saved, err := controlstatedb.New(tx).GetService(ctx, binding.ServiceID.String)
		if err != nil {
			return result, err
		}
		metadata, err := checkedServiceMetadata(saved)
		if err != nil {
			return result, err
		}
		result.Targets[binding.Service] = deploymentTarget(service)
		result.Services[binding.Service] = DeploymentService{ID: saved.ID, Protocol: metadata.Protocol, TrustRevision: metadata.TrustRevision, Endpoint: metadata.Endpoint}
	}
	if access.grantID != "" && len(result.Services) == 0 {
		return Deployment{}, ErrDeploymentNotFound
	}
	return result, nil
}
