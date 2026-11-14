package state

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	targetsyntax "github.com/tnldotdev/tnl/internal/policy/target"
)

type DeploymentPublication struct {
	PublicURL PublicURL
	Limits    *ProjectPublicLimits
}

// publishing is not management. acquire team/project/deployment parents,
// select the exact binding, then lock the URL before the signing identity.
func (d *Database) deploymentPublicationSelection(ctx context.Context, tx pgx.Tx, scope DeploymentScope, selector string, now time.Time) (PublisherIdentity, controlstatedb.ControlDeploymentManagementGrant, controlstatedb.ControlDeployment, error) {
	var approval controlstatedb.ControlDeploymentManagementGrant
	var deployment controlstatedb.ControlDeployment
	q := controlstatedb.New(tx)
	if scope.AccessToken == "" {
		return PublisherIdentity{}, approval, deployment, ErrDeploymentAccess
	}
	if _, err := q.LockLocalTeamForMutation(ctx, scope.TeamID); err != nil {
		return PublisherIdentity{}, approval, deployment, publisherLookupError(err, ErrDeploymentAccess)
	}
	if _, err := q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: scope.TeamID, ProjectKey: scope.ProjectKey}); err != nil {
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
	deployment, err = q.LockDeployment(ctx, controlstatedb.LockDeploymentParams{TeamID: scope.TeamID, ProjectKey: scope.ProjectKey, Selector: selector})
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

func (d *Database) GetDeploymentPublication(ctx context.Context, scope DeploymentScope, selector, service string, now time.Time) (result DeploymentPublication, retErr error) {
	clock := newAuthorizationClock(now)
	if !naming.ValidServiceName(service) {
		return result, ErrDeploymentAccess
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "read deployment publication", &retErr)()
	p, _, deployment, err := d.deploymentPublicationSelection(ctx, tx, scope, selector, clock.current())
	if err != nil {
		return result, err
	}
	var id string
	if err = tx.QueryRow(ctx, `SELECT public_url_id FROM control.applied_project_services WHERE deployment_id=$1 AND service=$2 AND public_url_id IS NOT NULL`, deployment.ID, service).Scan(&id); err != nil {
		return result, publisherLookupError(err, ErrDeploymentAccess)
	}
	q := controlstatedb.New(tx)
	u, err := q.LockPublicURLForRun(ctx, id)
	if err != nil {
		return result, err
	}
	if _, err = d.currentDeploymentPublication(ctx, q, scope.AccessToken, clock, true); err != nil {
		return result, err
	}
	if err = publisherOwnsRun(ctx, q, p, u); err != nil {
		if errors.Is(err, ErrPublisherIdentity) {
			return result, ErrDeploymentAccess
		}
		return result, err
	}
	snapshot, err := d.openDeploymentConfiguration(deployment)
	if err != nil {
		return result, err
	}
	s, ok := snapshot.Services[service]
	if !ok || s.Protocol != "http" || s.PublicURL == nil {
		return result, ErrDeploymentAccess
	}
	result.PublicURL = publicURLFromModel(u, "")
	result.PublicURL.AllowedIPPrefixes, err = d.openIPPolicy(u.ID, u.AllowedIpPolicyStorageKeyID.String, u.AllowedIpPolicyCiphertext)
	if err != nil {
		return DeploymentPublication{}, err
	}
	result.Limits = s.PublicURL.Limits
	if _, err = d.currentDeploymentPublication(ctx, q, scope.AccessToken, clock, false); err != nil {
		return DeploymentPublication{}, err
	}
	return result, tx.Commit(ctx)
}

type AllocateDeploymentPublicationRequest struct {
	DeploymentScope
	Deployment, Invocation, Target string
	Prefixes                       []string
	Binding                        []byte
	Options                        PublisherPublicURLOptions
	Now                            time.Time
}

// only the allocation decision is new. URLs, expiry, run credentials, DNS,
// certificates, visitor policy, and deletion use their existing owners.
func (d *Database) AllocateDeploymentPublication(ctx context.Context, r AllocateDeploymentPublicationRequest) (result PublicURL, retErr error) {
	clock := newAuthorizationClock(r.Now)
	if !opaqueid.Valid(r.Invocation, opaqueid.InvocationPrefix) || !r.Options.AccessMode.Valid() {
		return result, ErrPublicURLInvalid
	}
	if _, err := targetsyntax.ParseCanonicalTarget(r.Target); err != nil {
		return result, ErrPublicURLInvalid
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "allocate deployment publication", &retErr)()
	p, approval, deployment, err := d.deploymentPublicationSelection(ctx, tx, r.DeploymentScope, r.Deployment, clock.current())
	if err != nil {
		return result, err
	}
	if approval.TemporaryPublication == "" || r.Options.AccessMode == VisitorAccessAnonymous && approval.TemporaryPublication != "anonymous" {
		return result, ErrDeploymentAccess
	}
	q := controlstatedb.New(tx)
	encoded, err := json.Marshal([]any{p.ID, p.GrantID, deployment.ID, r.Invocation, r.Target, r.Prefixes, r.Binding, r.Options})
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256(encoded)
	existing, err := q.FindDeploymentPublicationAllocation(ctx, controlstatedb.FindDeploymentPublicationAllocationParams{PublisherIdentityID: p.ID, PublisherGrantID: p.GrantID, InvocationID: r.Invocation})
	if err == nil {
		u, err := q.LockPublicURLForRun(ctx, existing.PublicURLID)
		if err != nil {
			return result, err
		}
		if _, err = d.currentDeploymentPublication(ctx, q, r.AccessToken, clock, true); err != nil {
			return result, err
		}
		if existing.DeploymentID.String != deployment.ID || u.LifecycleState != "enabled" || !u.ExpiresAt.Valid || !u.ExpiresAt.Time.After(clock.current()) {
			return result, ErrPublicURLIdempotency
		}
		if err = publisherOwnsRun(ctx, q, p, u); err != nil {
			return result, err
		}
		stored, _, err := d.openSecret(u.RequestDigestStorageKeyID.String, publicURLRequestDigestContext(u.ID), u.RequestDigestCiphertext)
		if err != nil {
			return result, err
		}
		if subtle.ConstantTimeCompare(stored, digest[:]) != 1 {
			return result, ErrPublicURLIdempotency
		}
		result = publicURLFromModel(u, "")
		result.AllowedIPPrefixes, err = d.openIPPolicy(u.ID, u.AllowedIpPolicyStorageKeyID.String, u.AllowedIpPolicyCiphertext)
		if err != nil {
			return PublicURL{}, err
		}
		if _, err = d.currentDeploymentPublication(ctx, q, r.AccessToken, clock, false); err != nil {
			return PublicURL{}, err
		}
		return result, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
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
	hostname, err := newEphemeralHostname(deployment.Namespace)
	if err != nil {
		return result, err
	}
	key := sha256.Sum256([]byte(p.ID + "\x00" + p.GrantID + "\x00" + r.Invocation))
	request := CreatePublicURLRequest{TeamID: r.TeamID, DomainID: domain.ID, ActingIdentityID: p.CreatorID, IdempotencyKey: "deployment/" + hex.EncodeToString(key[:]), RequestDigest: digest, CanonicalHostname: hostname, Target: r.Target, ServiceProtocol: PublicURLServiceHTTP, PublicURLScope: PublicURLScopeShared, Purpose: PublicURLPurposeApp, AccessMode: r.Options.AccessMode, AllowedIPPrefixes: r.Prefixes, RequirePostQuantum: r.Options.RequirePostQuantum, Ephemeral: true, DNSState: PublicURLDNSPending, DNSAuthorityReference: domain.DnsAuthorityReference.String}
	prefixes, err := validateCreatePublicURLRequest(request)
	if err != nil {
		return result, err
	}
	if _, err = d.currentDeploymentPublication(ctx, q, r.AccessToken, clock, true); err != nil {
		return result, err
	}
	allowed, err := q.LockPublicURLCreationControl(ctx)
	if err != nil {
		return result, err
	}
	if !allowed {
		return result, ErrPublicURLCreationGated
	}
	var ingress string
	var revision int64
	if err = tx.QueryRow(ctx, `SELECT ingress_pool_id,policy_revision FROM control.teams WHERE id=$1`, r.TeamID).Scan(&ingress, &revision); err != nil {
		return result, err
	}
	u, err := d.insertPublicURL(ctx, tx, q, request, deployment.Namespace, ingress, revision, prefixes, r.Now)
	if err != nil {
		return result, err
	}
	if err = q.InsertPublisherAllocation(ctx, controlstatedb.InsertPublisherAllocationParams{PublicURLID: u.ID, PublisherIdentityID: p.ID, PublisherGrantID: p.GrantID, InvocationID: r.Invocation, DeploymentID: text(deployment.ID)}); err != nil {
		return result, err
	}
	if err = q.InsertPublicURLCreateAuditEvent(ctx, controlstatedb.InsertPublicURLCreateAuditEventParams{ActorIdentityID: text(p.CreatorID), RequestID: request.IdempotencyKey, PublicURLID: u.ID, OccurredAt: timestamptz(r.Now)}); err != nil {
		return result, err
	}
	if _, err = d.currentDeploymentPublication(ctx, q, r.AccessToken, clock, false); err != nil {
		return result, err
	}
	result = publicURLFromModel(u, "")
	if len(prefixes) > 0 {
		result.AllowedIPPrefixes = prefixes
	}
	return result, tx.Commit(ctx)
}
