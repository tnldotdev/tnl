package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

const DeploymentManagementGrant = "deployment_management"

var ErrDeploymentAccess = errors.New("deployment operation is outside the current credential approval")
var ErrDeploymentCredentialUnavailable = errors.New("original deployment credential approval is no longer usable")

type RegisterDeploymentManagementRequest struct {
	DeploymentScope
	Name, IdempotencyKey string
	PublicKey            ed25519.PublicKey
	Services             []string
	DeploymentIDs        []string
	AllDeployments       bool
	Lifetime             time.Duration
	Now                  time.Time
}

type DeploymentManagementCredential struct {
	ClientID       string            `json:"client_id"`
	KeyID          string            `json:"key_id"`
	GrantID        string            `json:"grant_id"`
	TeamID         string            `json:"team_id"`
	ProjectKey     string            `json:"project_key"`
	Services       map[string]string `json:"services"`
	DeploymentIDs  []string          `json:"deployment_ids"`
	AllDeployments bool              `json:"all_deployments"`
	ExpiresAt      time.Time         `json:"expires_at"`
}

type deploymentManagementScope struct{ team string }

func (s deploymentManagementScope) publisherScope() PublisherScope {
	return PublisherScope{TeamID: s.team, Kind: DeploymentManagementGrant}
}

// registration is manager-only. control stores the public key, not a second
// bootstrap secret or signing engine. the original key recovers one fixed grant.
func (d *Database) RegisterDeploymentManagement(ctx context.Context, r RegisterDeploymentManagementRequest) (result DeploymentManagementCredential, retErr error) {
	clock := newAuthorizationClock(r.Now)
	if r.AccessToken != "" || !naming.ValidServiceName(r.Name) || !validIdempotencyKey(r.IdempotencyKey) || len(r.PublicKey) != ed25519.PublicKeySize ||
		len(r.Services) < 1 || len(r.Services) > 128 || len(r.DeploymentIDs) > 128 || r.AllDeployments == (len(r.DeploymentIDs) > 0) || r.Lifetime < time.Minute || r.Lifetime > 30*24*time.Hour {
		return result, ErrProjectConfigurationInvalid
	}
	r.Services, r.DeploymentIDs = slices.Clone(r.Services), slices.Clone(r.DeploymentIDs)
	slices.Sort(r.Services)
	slices.Sort(r.DeploymentIDs)
	for i, name := range r.Services {
		if !naming.ValidServiceName(name) || i > 0 && name == r.Services[i-1] {
			return result, ErrProjectConfigurationInvalid
		}
	}
	for i, id := range r.DeploymentIDs {
		if !opaqueid.Valid(id, "pgrp_") || i > 0 && id == r.DeploymentIDs[i-1] {
			return result, ErrProjectConfigurationInvalid
		}
	}
	intent, err := json.Marshal(struct {
		Name                    string
		PublicKey               []byte
		Services, DeploymentIDs []string
		AllDeployments          bool
		Lifetime                time.Duration
	}{r.Name, r.PublicKey, r.Services, r.DeploymentIDs, r.AllDeployments, r.Lifetime})
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256(intent)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "register deployment management", &retErr)()
	if _, err = lockDeploymentManager(ctx, tx, r.DeploymentScope); err != nil {
		return result, err
	}
	q := controlstatedb.New(tx)
	recovered, err := q.FindDeploymentManagementRequest(ctx, controlstatedb.FindDeploymentManagementRequestParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, IdempotencyKey: r.IdempotencyKey})
	if err == nil {
		approval := recovered.ControlDeploymentManagementGrant
		if !bytes.Equal(approval.RequestDigest, digest[:]) {
			return result, ErrServiceConflict
		}
		identity, _, err := d.livePublisher(ctx, q, recovered.PublisherIdentityID, approval.GrantID, "", clock.current())
		if err != nil {
			if errors.Is(err, ErrPublisherIdentity) {
				return result, ErrDeploymentCredentialUnavailable
			}
			return result, err
		}
		key, err := q.GetPublisherKey(ctx, controlstatedb.GetPublisherKeyParams{ID: approval.InitialKeyID, PublisherIdentityID: identity.ID})
		if err != nil {
			return result, publisherLookupError(err, ErrPublisherIdentity)
		}
		if key.RetiredAt.Valid || !bytes.Equal(key.PublicKey, r.PublicKey) {
			return result, ErrDeploymentCredentialUnavailable
		}
		result = DeploymentManagementCredential{ClientID: identity.ID, KeyID: key.ID, GrantID: approval.GrantID, TeamID: r.TeamID, ProjectKey: r.ProjectKey, AllDeployments: approval.AllDeployments, ExpiresAt: recovered.ExpiresAt.Time.UTC()}
	} else {
		if !errors.Is(err, pgx.ErrNoRows) {
			return result, err
		}
		for _, id := range r.DeploymentIDs {
			if _, err = q.LockDeployment(ctx, controlstatedb.LockDeploymentParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey, Selector: id}); err != nil {
				return result, publisherLookupError(err, ErrDeploymentNotFound)
			}
		}
		declarations, err := q.ListProjectServiceDeclarations(ctx, controlstatedb.ListProjectServiceDeclarationsParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
		if err != nil {
			return result, err
		}
		protocols := map[string]string{}
		for _, declaration := range declarations {
			protocols[declaration.Name] = declaration.Protocol
		}
		for _, name := range r.Services {
			if protocols[name] == "" {
				return result, ErrProjectConfigurationInvalid
			}
		}
		until := r.Now.Add(r.Lifetime).UTC().Truncate(time.Microsecond)
		identity, err := insertPublisher(ctx, q, deploymentManagementScope{r.TeamID}, r.Name, "automation", r.ActorID, "", "team", "", r.PublicKey, &until, r.Now)
		if err != nil {
			return result, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO control.deployment_management_grants(grant_id,team_id,project_key,all_deployments,created_by_identity_id,idempotency_key,request_digest,initial_key_id)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, identity.GrantID, r.TeamID, r.ProjectKey, r.AllDeployments, r.ActorID, r.IdempotencyKey, digest[:], identity.KeyID)
		if err != nil {
			return result, err
		}
		for _, id := range r.DeploymentIDs {
			if _, err = tx.Exec(ctx, `INSERT INTO control.deployment_management_deployments(grant_id,team_id,project_key,deployment_id) VALUES($1,$2,$3,$4)`, identity.GrantID, r.TeamID, r.ProjectKey, id); err != nil {
				return result, err
			}
		}
		for _, name := range r.Services {
			if _, err = tx.Exec(ctx, `INSERT INTO control.deployment_management_services(grant_id,team_id,project_key,service,protocol) VALUES($1,$2,$3,$4,$5)`, identity.GrantID, r.TeamID, r.ProjectKey, name, protocols[name]); err != nil {
				return result, err
			}
		}
		result = DeploymentManagementCredential{ClientID: identity.ID, KeyID: identity.KeyID, GrantID: identity.GrantID, TeamID: r.TeamID, ProjectKey: r.ProjectKey, AllDeployments: r.AllDeployments, ExpiresAt: until}
	}
	result.Services, result.DeploymentIDs, err = deploymentManagementSelection(ctx, q, result.GrantID)
	if err != nil {
		return DeploymentManagementCredential{}, err
	}
	if !result.ExpiresAt.After(clock.current()) {
		return DeploymentManagementCredential{}, ErrDeploymentCredentialUnavailable
	}
	if err = commitDeployment(ctx, tx, r.DeploymentScope); err != nil {
		return DeploymentManagementCredential{}, err
	}
	return result, nil
}

func deploymentManagementSelection(ctx context.Context, q *controlstatedb.Queries, grant string) (map[string]string, []string, error) {
	services, err := q.ListDeploymentManagementServices(ctx, grant)
	if err != nil {
		return nil, nil, err
	}
	ids, err := q.ListDeploymentManagementDeployments(ctx, grant)
	if err != nil {
		return nil, nil, err
	}
	if ids == nil {
		ids = []string{}
	}
	result := map[string]string{}
	for _, service := range services {
		result[service.Service] = service.Protocol
	}
	return result, ids, nil
}

// authority is resolved again inside the operation's team/project transaction.
// the HTTP lookup, creator identity, and a previous successful call grant nothing.
type deploymentAccess struct {
	scope                         DeploymentScope
	clock                         authorizationClock
	actorID, principalID, grantID string
	services                      map[string]string
	deployments                   []string
	allDeployments                bool
	expiresAt                     time.Time
}

func (d *Database) lockDeploymentAccess(ctx context.Context, tx pgx.Tx, scope DeploymentScope, now time.Time) (access deploymentAccess, project controlstatedb.ControlAppliedProject, err error) {
	access = deploymentAccess{scope: scope, clock: newAuthorizationClock(now), actorID: scope.ActorID, principalID: scope.ActorID}
	if scope.AccessToken == "" {
		project, err = lockDeploymentManager(ctx, tx, scope)
		return access, project, err
	}
	if _, signed := serviceActor(ctx); signed {
		return access, project, ErrDeploymentAccess
	}
	q := controlstatedb.New(tx)
	if _, err = q.LockLocalTeamForMutation(ctx, scope.TeamID); err != nil {
		return access, project, publisherLookupError(err, ErrDeploymentAccess)
	}
	project, err = q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: scope.TeamID, ProjectKey: scope.ProjectKey})
	if err != nil {
		return access, project, publisherLookupError(err, ErrDeploymentNotFound)
	}
	identity, err := d.authenticatePublisherAccess(ctx, q, scope.AccessToken, "", access.clock.current(), false)
	if err != nil {
		return access, project, err
	}
	if identity.Scope.TeamID != scope.TeamID || identity.Scope.Kind != DeploymentManagementGrant {
		return access, project, ErrDeploymentAccess
	}
	approval, err := q.GetDeploymentManagementGrant(ctx, identity.GrantID)
	if err != nil {
		return access, project, publisherLookupError(err, ErrDeploymentAccess)
	}
	if approval.TeamID != scope.TeamID || approval.ProjectKey != scope.ProjectKey {
		return access, project, ErrDeploymentAccess
	}
	access.actorID, access.principalID, access.grantID = identity.CreatorID, identity.ID, identity.GrantID
	grant, err := q.ReadPublisherGrant(ctx, controlstatedb.ReadPublisherGrantParams{ID: identity.GrantID, PublisherIdentityID: identity.ID})
	if err != nil {
		return access, project, err
	}
	access.expiresAt = grant.ExpiresAt.Time
	access.allDeployments = approval.AllDeployments
	access.services, access.deployments, err = deploymentManagementSelection(ctx, q, identity.GrantID)
	return access, project, err
}

func (a deploymentAccess) deploymentAllowed(id string) bool {
	return a.grantID == "" || a.allDeployments || slices.Contains(a.deployments, id)
}

func (a deploymentAccess) auditActor() (person, publisher string) {
	if a.grantID != "" {
		return "", a.principalID
	}
	return a.actorID, ""
}

func (a deploymentAccess) setAuditActor(ctx context.Context, tx pgx.Tx) error {
	if a.grantID == "" {
		return SetServiceAuditActor(ctx, tx, a.actorID)
	}
	_, err := tx.Exec(ctx, `SELECT set_config('tnl.audit_actor','',true)`)
	return err
}

func (a deploymentAccess) recordUpdate(ctx context.Context, tx pgx.Tx, id, request string, now time.Time) error {
	person, publisher := a.auditActor()
	return recordPublisherGroupUpdate(ctx, tx, id, person, publisher, request, now)
}

// take identity locks after publication parents, but before any audit/routing
// clock. an identity may also carry an independently approved publication grant.
// the commit check then spends elapsed waits without acquiring a new lock order.
func (d *Database) lockDeploymentMutation(ctx context.Context, tx pgx.Tx, a deploymentAccess) error {
	if a.grantID == "" {
		return nil
	}
	if err := lockPublisherPublications(ctx, tx, a.scope.TeamID, a.principalID, ""); err != nil {
		return err
	}
	_, err := d.authenticatePublisherAccess(ctx, controlstatedb.New(tx), a.scope.AccessToken, "", a.clock.current(), true)
	return err
}

func (a deploymentAccess) servicesAllowed(names []string) error {
	if a.grantID == "" {
		return nil
	}
	for _, name := range names {
		if a.services[name] == "" {
			return ErrDeploymentAccess
		}
	}
	return nil
}

func (d *Database) commitDeploymentAccess(ctx context.Context, tx pgx.Tx, a deploymentAccess) error {
	if a.grantID == "" {
		return commitDeployment(ctx, tx, a.scope)
	}
	if _, err := d.authenticatePublisherAccess(ctx, controlstatedb.New(tx), a.scope.AccessToken, "", a.clock.current(), true); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (a deploymentAccess) publisherAllowed(ctx context.Context, q *controlstatedb.Queries, publisher string) error {
	if a.grantID == "" {
		return nil
	}
	allowed, err := q.DeploymentManagementPublisherAllowed(ctx, controlstatedb.DeploymentManagementPublisherAllowedParams{GrantID: a.grantID, PublisherID: publisher})
	if err != nil {
		return err
	}
	if !allowed {
		return ErrDeploymentPublisherNotFound
	}
	return nil
}
