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
	TeamID, GuestID, Kind, ServiceID, DomainID, Namespace, MembershipID string
	NamespaceScope                                                      NamespaceScope
}

// resolvedPublisherScope is a transaction-authorized grant target. submitted
// scopes are DTOs; only authorization and persisted enrollment validation may
// construct these variants before passing them to grant persistence.
type resolvedPublisherScope interface {
	publisherScope() PublisherScope
}

type servicePublisherScope struct{ teamID, serviceID, guestID string }
type namespacePublisherScope struct {
	teamID, domainID, namespace, membershipID string
	namespaceScope                            NamespaceScope
}

func (s servicePublisherScope) publisherScope() PublisherScope {
	return PublisherScope{TeamID: s.teamID, GuestID: s.guestID, Kind: "service", ServiceID: s.serviceID}
}

func (s namespacePublisherScope) publisherScope() PublisherScope {
	return PublisherScope{TeamID: s.teamID, Kind: "namespace", DomainID: s.domainID, Namespace: s.namespace, MembershipID: s.membershipID, NamespaceScope: s.namespaceScope}
}

// applied services have already been authorized under the project/team guard.
// their saved target, rather than a caller's submitted scope, determines grants.
func publisherScopeForAppliedService(s controlstatedb.ControlAppliedProjectService) resolvedPublisherScope {
	return servicePublisherScope{teamID: s.TeamID, serviceID: s.ServiceID.String}
}

type PublisherIdentity struct {
	ID, KeyID, GrantID, CreatorID, Kind, GuestID string
	Ownership, OwnerMembershipID                 string
	Scope                                        PublisherScope
	ExpiresAt                                    *time.Time
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
	return PublisherScope{TeamID: team, GuestID: g.GuestID.String, Kind: g.Kind, ServiceID: g.ServiceID.String, DomainID: g.DomainID.String, Namespace: g.Namespace.String, MembershipID: g.MembershipID.String, NamespaceScope: NamespaceScope(g.NamespaceScope.String)}
}

// authorizePublisherScope captures an explicit grant after checking the current
// editor under team/membership locks. grant use never consults that membership.
func (d *Database) authorizePublisherScope(ctx context.Context, tx pgx.Tx, q *controlstatedb.Queries, scope PublisherScope, editor, membership string, revision uint64) (resolvedPublisherScope, error) {
	if !validStateText(editor) || revision == 0 || scope.GuestID != "" {
		return nil, ErrPublisherIdentity
	}
	if _, err := q.LockLocalTeamForMutation(ctx, scope.TeamID); err != nil {
		return nil, err
	}
	m, err := q.GetTeamActorContext(ctx, controlstatedb.GetTeamActorContextParams{TeamID: scope.TeamID, IdentityID: editor})
	if err != nil {
		return nil, publisherLookupError(err, ErrPublisherIdentity)
	}
	if m.ActorMembershipID != membership || m.PolicyRevision != int64(revision) {
		return nil, ErrPublisherIdentity
	}
	if err := requireTeamSession(ctx, q, scope.TeamID, editor, time.Now()); err != nil {
		if errors.Is(err, ErrAuthorityAccess) {
			return nil, ErrPublisherIdentity
		}
		return nil, err
	}
	if scope.Kind == "service" {
		if !opaqueid.Valid(scope.ServiceID, opaqueid.ServicePrefix) || scope.DomainID != "" || scope.Namespace != "" ||
			scope.MembershipID != "" || scope.NamespaceScope != "" || m.ActorRole != "owner" && m.ActorRole != "admin" {
			return nil, ErrPublisherIdentity
		}
		s, err := q.LockService(ctx, scope.ServiceID)
		if err != nil {
			return nil, publisherLookupError(err, ErrPublisherIdentity)
		}
		if s.TeamID.String != scope.TeamID || s.GuestID.Valid || !s.Enabled || s.DeletedAt.Valid {
			return nil, ErrPublisherIdentity
		}
		if err := rejectAllocatedExactPublisher(ctx, q, s.ID); err != nil {
			return nil, err
		}
		return servicePublisherScope{teamID: scope.TeamID, serviceID: s.ID}, nil
	}
	if scope.Kind != "namespace" || scope.ServiceID != "" {
		return nil, ErrPublisherIdentity
	}
	c, err := serviceHostnameAuthority(ctx, tx, scope.TeamID, editor, scope.DomainID, time.Now())
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
	scope.NamespaceScope, scope.MembershipID = NamespaceScopeMember, m.ActorMembershipID
	if direct {
		scope.NamespaceScope, scope.MembershipID = NamespaceScopeShared, ""
	}
	return namespacePublisherScope{scope.TeamID, scope.DomainID, scope.Namespace, scope.MembershipID, scope.NamespaceScope}, nil
}

func rejectAllocatedExactPublisher(ctx context.Context, q *controlstatedb.Queries, service string) error {
	if _, err := q.GetPublisherAllocation(ctx, service); err == nil {
		return ErrPublisherIdentity
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	return nil
}

func resolvePublisherScope(ctx context.Context, q *controlstatedb.Queries, s PublisherScope, guest string) (resolvedPublisherScope, error) {
	if err := validatePublisherScope(ctx, q, s, guest); err != nil {
		return nil, err
	}
	switch s.Kind {
	case "service":
		return servicePublisherScope{teamID: s.TeamID, serviceID: s.ServiceID, guestID: s.GuestID}, nil
	case "namespace":
		return namespacePublisherScope{s.TeamID, s.DomainID, s.Namespace, s.MembershipID, s.NamespaceScope}, nil
	default:
		return nil, ErrPublisherIdentity
	}
}

// live-run checks validate current scope availability without creating a grant.
// resolution uses the same checks before constructing a persistence-only scope.
func validatePublisherScope(ctx context.Context, q *controlstatedb.Queries, s PublisherScope, guest string) error {
	if s.Kind == "service" {
		if !opaqueid.Valid(s.ServiceID, opaqueid.ServicePrefix) || s.DomainID != "" || s.Namespace != "" ||
			s.MembershipID != "" || s.NamespaceScope != "" || s.GuestID != guest || (s.TeamID == "") != (guest != "") {
			return ErrPublisherIdentity
		}
		service, err := q.LockService(ctx, s.ServiceID)
		if err != nil {
			return publisherLookupError(err, ErrPublisherIdentity)
		}
		if service.TeamID.String != s.TeamID || service.GuestID.String != guest || service.DeletedAt.Valid || !service.Enabled {
			return ErrPublisherIdentity
		}
		return rejectAllocatedExactPublisher(ctx, q, service.ID)
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
