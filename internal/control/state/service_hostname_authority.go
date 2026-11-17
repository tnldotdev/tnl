package state

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

// ServiceHostnameError contains only the current actor's default namespace on a
// ready authorized domain. it never describes the rejected hostname's owner.
type ServiceHostnameError struct {
	Namespace string
}

func (e *ServiceHostnameError) Error() string {
	return "service hostname is not permitted; use a hostname below " + e.Namespace
}
func (e *ServiceHostnameError) Unwrap() error { return ErrServiceAccess }

func hostnameWithin(hostname, domain string) bool {
	return hostname == domain || strings.HasSuffix(hostname, "."+domain)
}

type serviceHostnameFacts struct {
	ActorMembershipID, ActorManagedLabel, ActorMemberSlug, IngressPoolID string
	ActorRole, TeamKind, TeamDisplayName, TeamManagedLabel               string
	DomainKind, CanonicalDomain, DomainState                             string
	DomainTeamID                                                         pgtype.Text
}

// callers hold the team mutation guard. use snapshots rather than acquiring a
// domain row lock after the service lock; domain changes use the opposite order.
func serviceHostnameAuthority(ctx context.Context, tx pgx.Tx, team, actor, domain string, now time.Time) (facts serviceHostnameFacts, err error) {
	err = tx.QueryRow(ctx, `SELECT member.id,member.managed_label,reservation.member_slug,team.ingress_pool_id,
	    member.role,team.kind,team.display_name,team.managed_label,
	    domain.kind,domain.team_id,domain.canonical_domain,domain.state
	    FROM control.team_memberships member
	    JOIN control.member_slug_reservations reservation ON reservation.id=member.slug_reservation_id AND reservation.team_id=member.team_id
	    JOIN control.teams team ON team.id=member.team_id
	    JOIN control.identities person ON person.id=member.identity_id
	    JOIN control.domains domain ON domain.id=$3 AND domain.state='ready' AND domain.released_at IS NULL
	      AND (domain.kind='managed' OR domain.team_id=team.id)
	    WHERE member.team_id=$1 AND member.identity_id=$2 AND control.active_membership(member.id,$4)
	    AND person.disabled_at IS NULL AND team.deleted_at IS NULL`, team, actor, domain, now).Scan(
		&facts.ActorMembershipID, &facts.ActorManagedLabel, &facts.ActorMemberSlug, &facts.IngressPoolID,
		&facts.ActorRole, &facts.TeamKind, &facts.TeamDisplayName, &facts.TeamManagedLabel,
		&facts.DomainKind, &facts.DomainTeamID, &facts.CanonicalDomain, &facts.DomainState)
	return facts, publisherLookupError(err, ErrServiceAccess)
}

// service hostname authority is independent of protocol and public reachability.
// member names cannot claim their namespace apex or another member's descendants.
func authorizeServiceHostname(facts serviceHostnameFacts, labels []controlstatedb.ListTeamNamespaceLabelsRow, team, membership, hostname, scope string, mode naming.ManagedURLMode) error {
	if facts.DomainState != "ready" || facts.DomainKind == "custom" && facts.DomainTeamID.String != team ||
		facts.DomainKind == "managed" && facts.DomainTeamID.Valid || !hostnameWithin(hostname, facts.CanonicalDomain) {
		return ErrServiceAccess
	}
	actorNamespace, direct := naming.PublicURLNamespace(naming.NamespaceFacts{
		Domain: facts.CanonicalDomain, Managed: facts.DomainKind == "managed",
		Mode: mode, Personal: facts.TeamKind == "personal",
		TeamName: facts.TeamDisplayName, MemberSlug: facts.ActorMemberSlug, ManagedLabel: facts.ActorManagedLabel,
	})
	if scope == "member" {
		if direct || membership != facts.ActorMembershipID || hostname == actorNamespace || !hostnameWithin(hostname, actorNamespace) {
			return ErrServiceAccess
		}
		return nil
	}
	if scope != "shared" || membership != "" || facts.ActorRole != "admin" && facts.ActorRole != "owner" {
		return ErrServiceAccess
	}
	if facts.DomainKind == "managed" {
		namespace := naming.SharedPublicURLNamespace(facts.CanonicalDomain, true, mode, facts.TeamDisplayName, facts.TeamManagedLabel)
		if depth, within := naming.ChildDepth(hostname, namespace); !within || depth < 1 {
			return ErrServiceAccess
		}
		if facts.TeamKind == "organization" && mode == naming.ManagedURLModeSimple {
			for _, label := range labels {
				if hostnameWithin(hostname, label.MemberSlug+"."+namespace) {
					return ErrServiceAccess
				}
			}
		}
		return nil
	}
	for _, label := range labels {
		if hostnameWithin(hostname, label.MemberSlug+"."+facts.CanonicalDomain) {
			return ErrServiceAccess
		}
	}
	return nil
}
