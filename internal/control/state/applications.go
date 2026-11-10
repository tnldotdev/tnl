package state

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// application registrations reuse the existing durable signing identity. grants
// carry the operation separately from the resource, so possessing a visit grant
// cannot turn the same key into a publisher or namespace allocator.
type ApplicationOperation string

const (
	ApplicationVisit    ApplicationOperation = "visit"
	ApplicationPublish  ApplicationOperation = "publish"
	ApplicationAllocate ApplicationOperation = "allocate"
)

var ErrApplicationRegistration = errors.New("application registration or grant is invalid or unavailable")
var ErrApplicationIdempotency = errors.New("application registration request does not match its saved idempotency key")

type ApplicationGrantRequest struct {
	Operation ApplicationOperation
	Scope     PublisherScope
	ExpiresAt *time.Time
}

type RegisterApplicationRequest struct {
	TeamID, ActingIdentityID, Name, Ownership, IdempotencyKey string
	PublicKey                                                 ed25519.PublicKey
	Grants                                                    []ApplicationGrantRequest
}

type ApplicationGrant struct {
	ID                   string
	Operation            ApplicationOperation
	Scope                PublisherScope
	CreatedAt            time.Time
	ExpiresAt, RevokedAt *time.Time
}

type ApplicationRegistration struct {
	ID, KeyID, TeamID, Name, Ownership string
	Grants                             []ApplicationGrant
}

// this wrapper adds the authorized operation without copying resource scope
// validation or key ownership. only registration authorization constructs it.
type applicationGrantScope struct {
	resolvedPublisherScope
	operation ApplicationOperation
}

func (d *Database) RegisterApplication(ctx context.Context, r RegisterApplicationRequest, now time.Time) (result ApplicationRegistration, retErr error) {
	if !naming.ValidServiceName(r.Name) || len(r.PublicKey) != ed25519.PublicKeySize || len(r.Grants) < 1 || len(r.Grants) > 64 ||
		!validStateText(r.IdempotencyKey) || !opaqueid.Valid(r.ActingIdentityID, opaqueid.IdentityPrefix) ||
		(r.Ownership != "member" && r.Ownership != "team") {
		return result, ErrApplicationRegistration
	}
	encoded, err := json.Marshal(r)
	if err != nil {
		return result, ErrApplicationRegistration
	}
	digest := sha256.Sum256(encoded)
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer rollback(ctx, tx, "register application", &retErr)()
	q := controlstatedb.New(tx)
	if _, err := q.LockLocalTeamForMutation(ctx, r.TeamID); err != nil {
		return result, publisherLookupError(err, ErrApplicationRegistration)
	}
	if _, err := q.LockPublicURLCreator(ctx, r.ActingIdentityID); err != nil {
		return result, publisherLookupError(err, ErrApplicationRegistration)
	}
	member, err := q.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{TeamID: r.TeamID, IdentityID: r.ActingIdentityID})
	if err != nil {
		return result, publisherLookupError(err, ErrApplicationRegistration)
	}
	if err := requireTeamSession(ctx, q, r.TeamID, r.ActingIdentityID, now); err != nil {
		return result, err
	}
	if r.Ownership == "team" && member.Role != "owner" && member.Role != "admin" {
		return result, ErrApplicationRegistration
	}
	receipt, err := q.ReadApplicationRegistrationRequest(ctx, controlstatedb.ReadApplicationRegistrationRequestParams{IdentityID: r.ActingIdentityID, IdempotencyKey: r.IdempotencyKey})
	if err == nil {
		if subtle.ConstantTimeCompare(receipt.RequestDigest, digest[:]) != 1 {
			return result, ErrApplicationIdempotency
		}
		result, err = d.applicationRegistration(ctx, q, receipt.PublisherIdentityID, receipt.KeyID, receipt.GrantIds)
		if err != nil {
			return result, err
		}
		return result, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return result, err
	}
	resolved := make([]applicationGrantScope, 0, len(r.Grants))
	for _, request := range r.Grants {
		if request.Scope.TeamID != r.TeamID || request.ExpiresAt != nil && !request.ExpiresAt.After(now) {
			return result, ErrApplicationRegistration
		}
		scope, err := d.authorizeApplicationGrant(ctx, q, request, r.ActingIdentityID, member, r.Ownership, now)
		if err != nil {
			return result, err
		}
		resolved = append(resolved, scope)
	}
	owner := ""
	if r.Ownership == "member" {
		owner = member.ID
	}
	identity, err := insertPublisher(ctx, q, resolved[0], r.Name, "application", r.ActingIdentityID, "", r.Ownership, owner, r.PublicKey, r.Grants[0].ExpiresAt, now)
	if err != nil {
		return result, err
	}
	ids := []string{identity.GrantID}
	for index, scope := range resolved[1:] {
		grant, err := insertPublisherGrant(ctx, q, identity.ID, r.ActingIdentityID, scope, r.Grants[index+1].ExpiresAt, now)
		if err != nil {
			return result, err
		}
		ids = append(ids, grant.ID)
	}
	if err := q.RecordApplicationRegistrationRequest(ctx, controlstatedb.RecordApplicationRegistrationRequestParams{IdentityID: r.ActingIdentityID, IdempotencyKey: r.IdempotencyKey, RequestDigest: digest[:], PublisherIdentityID: identity.ID, KeyID: identity.KeyID, GrantIds: ids, CreatedAt: timestamptz(now)}); err != nil {
		return result, err
	}
	result, err = d.applicationRegistration(ctx, q, identity.ID, identity.KeyID, ids)
	if err != nil {
		return result, err
	}
	return result, tx.Commit(ctx)
}

func (d *Database) authorizeApplicationGrant(ctx context.Context, q *controlstatedb.Queries, request ApplicationGrantRequest, actor string, member controlstatedb.GetActivePublishRunMembershipRow, ownership string, now time.Time) (applicationGrantScope, error) {
	var scope resolvedPublisherScope
	var err error
	switch request.Operation {
	case ApplicationVisit:
		scope, err = d.authorizeApplicationVisit(ctx, q, request.Scope, actor, now)
	case ApplicationPublish:
		if request.Scope.Kind != "saved_public_url" && request.Scope.Kind != "service" {
			return applicationGrantScope{}, ErrApplicationRegistration
		}
		scope, err = d.authorizePublisherScope(ctx, q, request.Scope, actor, member.ID, uint64(member.PolicyRevision))
	case ApplicationAllocate:
		if request.Scope.Kind != "namespace" {
			return applicationGrantScope{}, ErrApplicationRegistration
		}
		scope, err = d.authorizePublisherScope(ctx, q, request.Scope, actor, member.ID, uint64(member.PolicyRevision))
	default:
		return applicationGrantScope{}, ErrApplicationRegistration
	}
	if err != nil {
		return applicationGrantScope{}, err
	}
	if err := publisherGrantMatchesOwnership(ctx, q, ownership, scope.publisherScope()); err != nil {
		return applicationGrantScope{}, err
	}
	return applicationGrantScope{scope, request.Operation}, nil
}

func (d *Database) authorizeApplicationVisit(ctx context.Context, q *controlstatedb.Queries, s PublisherScope, actor string, now time.Time) (resolvedPublisherScope, error) {
	if s.DomainID != "" || s.Namespace != "" || s.MembershipID != "" || s.PublicURLScope != "" {
		return nil, ErrApplicationRegistration
	}
	var scope resolvedPublisherScope
	kind, id := "", ""
	switch s.Kind {
	case "service":
		if s.PublicURLID != "" || !opaqueid.Valid(s.ServiceID, opaqueid.ServicePrefix) {
			return nil, ErrApplicationRegistration
		}
		resource, err := q.LockService(ctx, s.ServiceID)
		if err != nil {
			return nil, publisherLookupError(err, ErrApplicationRegistration)
		}
		if resource.TeamID != s.TeamID || !resource.Enabled || resource.DeletedAt.Valid {
			return nil, ErrApplicationRegistration
		}
		scope, kind, id = servicePublisherScope{s.TeamID, s.ServiceID}, "service", s.ServiceID
	case "saved_public_url":
		if s.ServiceID != "" || !opaqueid.Valid(s.PublicURLID, opaqueid.PublicURLPrefix) {
			return nil, ErrApplicationRegistration
		}
		resource, err := q.LockPublicURLForRun(ctx, s.PublicURLID)
		if err != nil {
			return nil, publisherLookupError(err, ErrApplicationRegistration)
		}
		if resource.TeamID != s.TeamID || resource.LifecycleState != "enabled" || (resource.Purpose != "app" && resource.Purpose != "alias" && resource.Purpose != "demo") || resource.ExpiresAt.Valid && !resource.ExpiresAt.Time.After(now) {
			return nil, ErrApplicationRegistration
		}
		scope, kind, id = savedURLPublisherScope{s.TeamID, s.PublicURLID}, "public_url", s.PublicURLID
	default:
		return nil, ErrApplicationRegistration
	}
	if _, err := q.VisitorPermission(ctx, controlstatedb.VisitorPermissionParams{ResourceKind: kind, ResourceID: id, IdentityID: actor, ControlSessionID: companySessionID(ctx, actor), Now: timestamptz(now)}); err != nil {
		return nil, publisherLookupError(err, ErrApplicationRegistration)
	}
	return scope, nil
}

func (d *Database) applicationRegistration(ctx context.Context, q *controlstatedb.Queries, id, key string, ids []string) (ApplicationRegistration, error) {
	identity, err := q.LockPublisherIdentity(ctx, id)
	if err != nil {
		return ApplicationRegistration{}, err
	}
	if identity.Kind != "application" || identity.RevokedAt.Valid {
		return ApplicationRegistration{}, ErrApplicationRegistration
	}
	current, err := q.GetPublisherKey(ctx, controlstatedb.GetPublisherKeyParams{ID: key, PublisherIdentityID: id})
	if err != nil {
		return ApplicationRegistration{}, err
	}
	if current.RetiredAt.Valid {
		return ApplicationRegistration{}, ErrApplicationRegistration
	}
	result := ApplicationRegistration{ID: id, KeyID: key, TeamID: identity.TeamID, Name: identity.Name, Ownership: identity.Ownership, Grants: make([]ApplicationGrant, 0, len(ids))}
	for _, id := range ids {
		grant, err := q.GetPublisherGrant(ctx, controlstatedb.GetPublisherGrantParams{ID: id, PublisherIdentityID: identity.ID})
		if err != nil {
			return ApplicationRegistration{}, err
		}
		result.Grants = append(result.Grants, ApplicationGrant{ID: grant.ID, Operation: ApplicationOperation(grant.Operation), Scope: scopeFromGrant(identity.TeamID, grant), CreatedAt: grant.CreatedAt.Time, ExpiresAt: optionalTime(grant.ExpiresAt), RevokedAt: optionalTime(grant.RevokedAt)})
	}
	return result, nil
}
