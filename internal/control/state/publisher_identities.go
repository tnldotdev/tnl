package state

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

var ErrPublisherIdentity = errors.New("publisher identity or grant is unavailable")
var ErrPublisherEnrollment = errors.New("publisher enrollment is invalid, expired, or consumed")

const PublisherEnrollmentLifetime = 10 * time.Minute
const PublisherAccessLifetime = 5 * time.Minute

type PublisherScope struct {
	TeamID, Kind, PublicURLID, ServiceID, DomainID, Namespace, MembershipID string
	PublicURLScope                                                          PublicURLScope
}

// resolvedPublisherScope is a transaction-authorized grant target. submitted
// scopes are DTOs; only authorization and persisted enrollment validation may
// construct these variants before passing them to grant persistence.
type resolvedPublisherScope interface {
	publisherScope() PublisherScope
}

type savedURLPublisherScope struct{ teamID, publicURLID string }
type servicePublisherScope struct{ teamID, serviceID string }
type namespacePublisherScope struct {
	teamID, domainID, namespace, membershipID string
	publicURLScope                            PublicURLScope
}

func (s savedURLPublisherScope) publisherScope() PublisherScope {
	return PublisherScope{TeamID: s.teamID, Kind: "saved_public_url", PublicURLID: s.publicURLID}
}

func (s servicePublisherScope) publisherScope() PublisherScope {
	return PublisherScope{TeamID: s.teamID, Kind: "service", ServiceID: s.serviceID}
}

func (s namespacePublisherScope) publisherScope() PublisherScope {
	return PublisherScope{TeamID: s.teamID, Kind: "namespace", DomainID: s.domainID, Namespace: s.namespace, MembershipID: s.membershipID, PublicURLScope: s.publicURLScope}
}

// applied services have already been authorized under the project/team guard.
// their saved target, rather than a caller's submitted scope, determines grants.
func publisherScopeForAppliedService(s controlstatedb.ControlAppliedProjectService) resolvedPublisherScope {
	if s.ServiceID.Valid {
		return servicePublisherScope{s.TeamID, s.ServiceID.String}
	}
	return savedURLPublisherScope{s.TeamID, s.PublicURLID.String}
}

type PublisherIdentity struct {
	ID, KeyID, GrantID, CreatorID, Kind, GuestID string
	Ownership, OwnerMembershipID                 string
	Scope                                        PublisherScope
}
type PublisherEnrollment struct {
	ID, Key string
	Scope   PublisherScope
	Until   time.Time
}
type PublisherAccess struct {
	PublisherIdentity
	Token string
	Until time.Time
}
type CreatePublisherEnrollmentRequest struct {
	Ownership                                string
	Scope                                    PublisherScope
	Name, Kind, EditorID, EditorMembershipID string
	PolicyRevision                           uint64
	Now                                      time.Time
}
type CreatePublisherGrantRequest struct {
	PublisherIdentityID          string
	Scope                        PublisherScope
	EditorID, EditorMembershipID string
	PolicyRevision               uint64
	ExpiresAt                    *time.Time
	Now                          time.Time
}

func publisherLookupError(err, unavailable error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return unavailable
	}
	return err
}

func scopeFromGrant(team string, g controlstatedb.ControlPublisherGrant) PublisherScope {
	return PublisherScope{TeamID: team, Kind: g.Kind, PublicURLID: g.PublicURLID.String, ServiceID: g.ServiceID.String, DomainID: g.DomainID.String, Namespace: g.Namespace.String, MembershipID: g.MembershipID.String, PublicURLScope: PublicURLScope(g.PublicURLScope.String)}
}

// authorizePublisherScope captures an explicit grant after checking the current
// editor under team/membership locks. grant use never consults that membership.
func (d *Database) authorizePublisherScope(ctx context.Context, q *controlstatedb.Queries, scope PublisherScope, editor, membership string, revision uint64) (resolvedPublisherScope, error) {
	if !validStateText(editor) || revision == 0 {
		return nil, ErrPublisherIdentity
	}
	if _, err := q.LockLocalTeamForMutation(ctx, scope.TeamID); err != nil {
		return nil, err
	}
	m, err := q.GetActivePublishRunMembership(ctx, controlstatedb.GetActivePublishRunMembershipParams{TeamID: scope.TeamID, IdentityID: editor})
	if err != nil {
		return nil, publisherLookupError(err, ErrPublisherIdentity)
	}
	if m.ID != membership || m.PolicyRevision != int64(revision) {
		return nil, ErrPublisherIdentity
	}
	if err := requireTeamSession(ctx, q, scope.TeamID, editor, time.Now()); err != nil {
		if errors.Is(err, ErrAuthorityAccess) {
			return nil, ErrPublisherIdentity
		}
		return nil, err
	}
	if scope.Kind == "service" {
		if !opaqueid.Valid(scope.ServiceID, opaqueid.ServicePrefix) || scope.PublicURLID != "" || scope.DomainID != "" || scope.Namespace != "" ||
			scope.MembershipID != "" || scope.PublicURLScope != "" || m.Role != "owner" && m.Role != "admin" {
			return nil, ErrPublisherIdentity
		}
		s, err := q.LockService(ctx, scope.ServiceID)
		if err != nil {
			return nil, publisherLookupError(err, ErrPublisherIdentity)
		}
		if s.TeamID != scope.TeamID || !s.Enabled || s.DeletedAt.Valid {
			return nil, ErrPublisherIdentity
		}
		return servicePublisherScope{scope.TeamID, s.ID}, nil
	}
	if scope.Kind == "saved_public_url" {
		if scope.ServiceID != "" || scope.DomainID != "" || scope.Namespace != "" {
			return nil, ErrPublisherIdentity
		}
		u, err := q.LockPublicURLForRun(ctx, scope.PublicURLID)
		if err != nil {
			return nil, publisherLookupError(err, ErrPublisherIdentity)
		}
		if u.TeamID != scope.TeamID || u.Ephemeral || u.LifecycleState != "enabled" || !PublicURLPurpose(u.Purpose).ValidForCreation() ||
			u.PublicURLScope == "member" && u.MembershipID.String != m.ID || u.PublicURLScope == "shared" && m.Role != "owner" && m.Role != "admin" {
			return nil, ErrPublisherIdentity
		}
		return savedURLPublisherScope{scope.TeamID, u.ID}, nil
	}
	if scope.Kind != "namespace" || scope.PublicURLID != "" || scope.ServiceID != "" {
		return nil, ErrPublisherIdentity
	}
	c, err := q.GetPublicURLCreationContext(ctx, controlstatedb.GetPublicURLCreationContextParams{IdentityID: editor, DomainID: scope.DomainID, TeamID: scope.TeamID})
	if err != nil {
		return nil, err
	}
	if c.DomainState != "ready" {
		return nil, ErrPublisherIdentity
	}
	ns, direct := naming.PublicURLNamespace(naming.NamespaceFacts{Domain: c.CanonicalDomain, Managed: c.DomainKind == "managed", Mode: d.managedURLMode, Personal: c.TeamKind == "personal", TeamName: c.TeamDisplayName, MemberSlug: c.ActorMemberSlug, ManagedLabel: c.ActorManagedLabel})
	if ns == "" || scope.Namespace != "" && scope.Namespace != ns {
		return nil, ErrPublisherIdentity
	}
	scope.Namespace = ns
	scope.PublicURLScope, scope.MembershipID = PublicURLScopeMember, m.ID
	if direct {
		scope.PublicURLScope, scope.MembershipID = PublicURLScopeShared, ""
	}
	return namespacePublisherScope{scope.TeamID, scope.DomainID, scope.Namespace, scope.MembershipID, scope.PublicURLScope}, nil
}

func resolvePublisherScope(ctx context.Context, q *controlstatedb.Queries, s PublisherScope, guest string) (resolvedPublisherScope, error) {
	if err := validatePublisherScope(ctx, q, s, guest); err != nil {
		return nil, err
	}
	switch s.Kind {
	case "service":
		return servicePublisherScope{s.TeamID, s.ServiceID}, nil
	case "saved_public_url":
		return savedURLPublisherScope{s.TeamID, s.PublicURLID}, nil
	case "namespace":
		return namespacePublisherScope{s.TeamID, s.DomainID, s.Namespace, s.MembershipID, s.PublicURLScope}, nil
	default:
		return nil, ErrPublisherIdentity
	}
}

// live-run checks validate current scope availability without creating a grant.
// resolution uses the same checks before constructing a persistence-only scope.
func validatePublisherScope(ctx context.Context, q *controlstatedb.Queries, s PublisherScope, guest string) error {
	if s.Kind == "service" {
		if guest != "" || !opaqueid.Valid(s.ServiceID, opaqueid.ServicePrefix) || s.PublicURLID != "" || s.DomainID != "" || s.Namespace != "" {
			return ErrPublisherIdentity
		}
		service, err := q.LockService(ctx, s.ServiceID)
		if err != nil {
			return publisherLookupError(err, ErrPublisherIdentity)
		}
		if service.TeamID != s.TeamID || service.DeletedAt.Valid || !service.Enabled {
			return ErrPublisherIdentity
		}
		return nil
	}
	if s.Kind == "saved_public_url" {
		if s.ServiceID != "" {
			return ErrPublisherIdentity
		}
		u, err := q.LockPublicURLForRun(ctx, s.PublicURLID)
		if err != nil {
			return publisherLookupError(err, ErrPublisherIdentity)
		}
		if u.TeamID != s.TeamID || u.LifecycleState != "enabled" || guest == "" && (u.Ephemeral || !PublicURLPurpose(u.Purpose).ValidForCreation()) {
			return ErrPublisherIdentity
		}
		if guest != "" {
			owned, err := q.GuestOwnsPublicURL(ctx, controlstatedb.GuestOwnsPublicURLParams{GuestID: guest, PublicURLID: u.ID})
			if err != nil || !owned || u.Purpose != "demo" {
				return ErrPublisherIdentity
			}
			return nil
		}
		_, err = q.GetPublisherDomain(ctx, controlstatedb.GetPublisherDomainParams{ID: u.DomainID, TeamID: text(s.TeamID)})
		return err
	}
	if s.Kind != "namespace" || guest != "" || s.ServiceID != "" {
		return ErrPublisherIdentity
	}
	domain, err := q.GetPublisherDomain(ctx, controlstatedb.GetPublisherDomainParams{ID: s.DomainID, TeamID: text(s.TeamID)})
	if err != nil {
		return publisherLookupError(err, ErrPublisherIdentity)
	}
	if s.Namespace != domain.CanonicalDomain && !strings.HasSuffix(s.Namespace, "."+domain.CanonicalDomain) {
		return ErrPublisherIdentity
	}
	return nil
}
