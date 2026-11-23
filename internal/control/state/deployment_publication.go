package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

// publishing is not management. acquire team/project/deployment parents,
// select the exact binding, then lock the service before the signing identity.
func (d *Database) deploymentPublicationSelection(ctx context.Context, tx pgx.Tx, scope DeploymentScope, selector string, now time.Time, mode deploymentLockMode) (PublisherIdentity, controlstatedb.ControlDeploymentManagementGrant, controlstatedb.ControlDeployment, error) {
	var approval controlstatedb.ControlDeploymentManagementGrant
	var deployment controlstatedb.ControlDeployment
	q := controlstatedb.New(tx)
	if scope.AccessToken == "" {
		return PublisherIdentity{}, approval, deployment, ErrDeploymentAccess
	}
	if err := mode.team(ctx, q, scope.TeamID); err != nil {
		return PublisherIdentity{}, approval, deployment, publisherLookupError(err, ErrDeploymentAccess)
	}
	if _, err := mode.project(ctx, q, scope.TeamID, scope.ProjectKey); err != nil {
		return PublisherIdentity{}, approval, deployment, publisherLookupError(err, ErrDeploymentAccess)
	}
	p, err := d.authenticatePublisherAccess(ctx, q, scope.AccessToken, "", now, false)
	if err != nil {
		return p, approval, deployment, err
	}
	if p.Scope.TeamID != scope.TeamID || p.Scope.Kind != DeploymentCredentialGrant {
		return p, approval, deployment, ErrDeploymentAccess
	}
	approval, err = q.GetDeploymentManagementGrant(ctx, p.GrantID)
	if err != nil {
		return p, approval, deployment, err
	}
	if approval.TeamID != scope.TeamID || approval.ProjectKey != scope.ProjectKey {
		return p, approval, deployment, ErrDeploymentAccess
	}
	deployment, err = mode.selectDeployment(ctx, q, scope.TeamID, scope.ProjectKey, selector)
	if err != nil {
		return p, approval, deployment, publisherLookupError(err, ErrDeploymentAccess)
	}
	if !approval.AllDeployments {
		ids, err := q.ListDeploymentManagementDeployments(ctx, p.GrantID)
		if err != nil {
			return p, approval, deployment, err
		}
		found := false
		for _, id := range ids {
			found = found || id == deployment.ID
		}
		if !found {
			return p, approval, deployment, ErrDeploymentAccess
		}
	}
	return p, approval, deployment, nil
}

// a current token alone is not proof that its signing key remains current.
// lock only after resource parents; recheck deadlines after possible waits.
func (d *Database) currentDeploymentPublication(ctx context.Context, q *controlstatedb.Queries, token string, clock authorizationClock, lock bool) (PublisherIdentity, error) {
	p, err := d.authenticatePublisherAccess(ctx, q, token, "", clock.current(), lock)
	if err != nil {
		return p, err
	}
	key, err := q.GetPublisherKey(ctx, controlstatedb.GetPublisherKeyParams{ID: p.KeyID, PublisherIdentityID: p.ID})
	if err != nil {
		return p, err
	}
	if p.Scope.Kind != DeploymentCredentialGrant || key.RetiredAt.Valid {
		return p, ErrPublisherIdentity
	}
	return p, nil
}

func (d *Database) GetDeploymentPublication(ctx context.Context, scope DeploymentScope, selector, service string, now time.Time) (result ServiceRecord, retErr error) {
	clock := newAuthorizationClock(now)
	if !naming.ValidServiceName(service) {
		return result, ErrDeploymentAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "read deployment publication", &retErr)()
	p, _, deployment, err := d.deploymentPublicationSelection(ctx, tx, scope, selector, clock.current(), deploymentRead)
	if err != nil {
		return result, err
	}
	var id string
	if err = tx.QueryRow(ctx, `SELECT service_id FROM control.applied_project_services WHERE deployment_id=$1 AND service=$2 AND service_id IS NOT NULL`, deployment.ID, service).Scan(&id); err != nil {
		return result, publisherLookupError(err, ErrDeploymentAccess)
	}
	q := controlstatedb.New(tx)
	if err = queueRunReader(ctx, tx, id); err != nil {
		return result, err
	}
	row, err := q.ObservePublisherEnrollmentService(ctx, id)
	if err != nil {
		return result, publisherLookupError(err, ErrDeploymentAccess)
	}
	if err := observeDeploymentCredential(ctx, tx, p.ID, p.GrantID); err != nil {
		return result, err
	}
	p, err = d.currentDeploymentPublication(ctx, q, scope.AccessToken, clock, false)
	if err != nil {
		return result, err
	}
	if row.Protocol != "http" {
		return result, ErrDeploymentAccess
	}
	if _, err = publisherServicePermission(ctx, tx, p.ID, p.GrantID, p.KeyID, id, clock.current()); err != nil {
		if errors.Is(err, ErrServiceAccess) {
			return result, errors.Join(ErrDeploymentAccess, err)
		}
		return result, err
	}
	result, err = d.publisherServiceRecord(ctx, tx, row)
	if err != nil {
		return ServiceRecord{}, err
	}
	if _, err = d.currentDeploymentPublication(ctx, q, scope.AccessToken, clock, false); err != nil {
		return ServiceRecord{}, err
	}
	if _, err = publisherServicePermission(ctx, tx, p.ID, p.GrantID, p.KeyID, id, clock.current()); err != nil {
		if errors.Is(err, ErrServiceAccess) {
			return ServiceRecord{}, errors.Join(ErrDeploymentAccess, err)
		}
		return ServiceRecord{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ServiceRecord{}, err
	}
	return result, nil
}

type AllocateDeploymentPublicationRequest struct {
	DeploymentScope
	AllocateServiceRequest
	Deployment string
	Now        time.Time
}

// temporary approval selects the same service allocator as namespace grants.
// named publication, management and connector approval grant no allocation right.
func (d *Database) AllocateDeploymentPublication(ctx context.Context, r AllocateDeploymentPublicationRequest) (result ServiceRecord, retErr error) {
	clock := newAuthorizationClock(r.Now)
	s, mode, err := normalizeServiceAllocation(r.AllocateServiceRequest)
	if err != nil {
		return result, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "allocate deployment publication", &retErr)()
	p, approval, deployment, err := d.deploymentPublicationSelection(ctx, tx, r.DeploymentScope, r.Deployment, clock.current(), deploymentMutation)
	if err != nil {
		return result, err
	}
	if approval.TemporaryPublication == "" || mode == "anonymous" && approval.TemporaryPublication != "anonymous" {
		return result, ErrDeploymentAccess
	}
	q := controlstatedb.New(tx)
	domain, err := q.GetPublisherDomain(ctx, controlstatedb.GetPublisherDomainParams{ID: deployment.DomainID.String, TeamID: text(r.TeamID)})
	if err != nil {
		return result, err
	}
	var claimed bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.service_namespace_claims WHERE deployment_id=$1 AND namespace=$2 AND domain_id=$3 AND retired_at IS NULL)`, deployment.ID, deployment.Namespace, domain.ID).Scan(&claimed); err != nil {
		return result, err
	}
	if !claimed || domain.Kind == "custom" && !domain.DnsAuthorityReference.Valid {
		return result, ErrDeploymentAccess
	}
	result, err = d.allocateService(ctx, tx, p, deployment.ID, domain.ID, deployment.Namespace, r.AllocateServiceRequest, s, mode, clock)
	if err != nil {
		return ServiceRecord{}, err
	}
	if _, err = tx.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
		return ServiceRecord{}, err
	}
	if _, err = d.currentDeploymentPublication(ctx, q, r.AccessToken, clock, true); err != nil {
		return ServiceRecord{}, err
	}
	if _, err = publisherServicePermission(ctx, tx, p.ID, p.GrantID, p.KeyID, result.ID, clock.current()); err != nil {
		return ServiceRecord{}, err
	}
	if _, err = d.currentDeploymentPublication(ctx, q, r.AccessToken, clock, false); err != nil {
		return ServiceRecord{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return ServiceRecord{}, err
	}
	return result, nil
}
