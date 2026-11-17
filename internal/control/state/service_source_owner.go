package state

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

// a source owner is the existing durable namespace claim, not a publisher or
// visitor grant. standalone creation and configuration use the same owner.
type serviceSourceOwner struct {
	scope            NamespaceScope
	membership, team string
	key              string
	local            bool
}

func (o serviceSourceOwner) valid(team string) bool {
	return o.key != "" && (o.scope == NamespaceScopeMember && o.membership != "" && o.team == "" ||
		o.scope == NamespaceScopeShared && o.membership == "" && o.team == team && !o.local)
}

func (o serviceSourceOwner) sourceKey(intent string) string {
	principal := o.membership
	if o.scope == NamespaceScopeShared {
		principal = "team/" + o.team
	}
	digest := sha256.Sum256([]byte(principal + "\x00" + intent))
	return fmt.Sprintf("%x", digest[:])
}

func (d *Database) newServiceSourceOwner(ctx context.Context, tx pgx.Tx, facts serviceHostnameFacts, team, hostname, intent string, standalone, explicit bool) (serviceSourceOwner, error) {
	if !explicit {
		// the endpoint owner already constructed this exact member/worktree
		// hostname. public naming defaults do not replace that captured scope.
		owner := serviceSourceOwner{scope: NamespaceScopeMember, membership: facts.ActorMembershipID, local: !standalone}
		owner.key = owner.sourceKey(intent)
		return owner, nil
	}
	namespace, direct := naming.PublicURLNamespace(naming.NamespaceFacts{
		Domain: facts.CanonicalDomain, Managed: facts.DomainKind == "managed", Mode: d.managedURLMode,
		Personal: facts.TeamKind == "personal", TeamName: facts.TeamDisplayName,
		MemberSlug: facts.ActorMemberSlug, ManagedLabel: facts.ActorManagedLabel,
	})
	scope, membership := NamespaceScopeShared, ""
	if !direct && hostname != namespace && hostnameWithin(hostname, namespace) {
		scope, membership = NamespaceScopeMember, facts.ActorMembershipID
	}
	if scope == NamespaceScopeShared && !standalone && facts.TeamKind != "personal" {
		return serviceSourceOwner{}, &ServiceHostnameError{Namespace: namespace}
	}
	labels, err := controlstatedb.New(tx).ListTeamNamespaceLabels(ctx, team)
	if err != nil {
		return serviceSourceOwner{}, err
	}
	if err := authorizeServiceHostname(facts, labels, team, membership, hostname, string(scope), d.managedURLMode); err != nil {
		return serviceSourceOwner{}, &ServiceHostnameError{Namespace: namespace}
	}
	owner := serviceSourceOwner{scope: scope, membership: membership, local: !standalone}
	if scope == NamespaceScopeShared {
		owner.team = team
	}
	// personal local-app associations retain their original membership/source
	// receipt even when their permitted hostname uses the shared personal name.
	if !standalone {
		owner.scope, owner.membership, owner.team = NamespaceScopeMember, facts.ActorMembershipID, ""
	}
	owner.key = owner.sourceKey(intent)
	return owner, nil
}

func storedServiceSourceOwner(ctx context.Context, tx pgx.Tx, service controlstatedb.ControlService, retained bool) (serviceSourceOwner, error) {
	var owner serviceSourceOwner
	var membership, team pgtype.Text
	var consistent bool
	err := tx.QueryRow(ctx, `SELECT endpoint.local_source_key,claim.membership_id,claim.owner_team_id,
	    EXISTS(SELECT 1 FROM control.local_project_services local WHERE local.service_id=service.id),
	    endpoint.namespace=endpoint.hostname AND endpoint.domain_id=service.domain_id
	      AND endpoint.deployment_id IS NULL AND claim.deployment_id IS NULL
	      AND NOT EXISTS(SELECT 1 FROM control.applied_project_services applied WHERE applied.service_id=service.id)
	      AND NOT EXISTS(SELECT 1 FROM control.publisher_namespace_allocations allocation WHERE allocation.service_id=service.id)
	      AND (SELECT count(*)=1 FROM control.service_endpoints current_endpoint
	          WHERE current_endpoint.service_id=service.id AND (current_endpoint.retired_at IS NULL OR $2 AND current_endpoint.hostname=service.certificate_hostname))
	      AND (claim.membership_id IS NULL OR EXISTS(SELECT 1 FROM control.team_memberships member
	          WHERE member.id=claim.membership_id AND member.team_id=service.team_id))
	    FROM control.services service
	    JOIN control.service_endpoints endpoint ON endpoint.service_id=service.id
	      AND endpoint.hostname=service.certificate_hostname AND (endpoint.retired_at IS NULL OR $2)
	    JOIN control.service_namespace_claims claim ON claim.namespace=endpoint.namespace
	      AND claim.local_source_key=endpoint.local_source_key AND claim.domain_id=endpoint.domain_id
	      AND (claim.retired_at IS NULL OR $2)
	    WHERE service.id=$1 AND service.guest_id IS NULL AND (service.deleted_at IS NULL OR $2)`,
		service.ID, retained).Scan(&owner.key, &membership, &team, &owner.local, &consistent)
	if err != nil {
		return serviceSourceOwner{}, publisherLookupError(err, ErrServiceAccess)
	}
	owner.scope, owner.membership = NamespaceScopeMember, membership.String
	if team.Valid {
		owner.scope, owner.team = NamespaceScopeShared, team.String
	}
	if !consistent || !owner.valid(service.TeamID.String) {
		return serviceSourceOwner{}, ErrServiceAccess
	}
	return owner, nil
}

func (d *Database) authorizeOwnedServiceHostname(ctx context.Context, tx pgx.Tx, facts serviceHostnameFacts, owner serviceSourceOwner, team, domain, hostname string, now time.Time) error {
	if !owner.valid(team) {
		return ErrServiceAccess
	}
	if owner.scope == NamespaceScopeMember && owner.membership != facts.ActorMembershipID {
		var identity string
		if err := tx.QueryRow(ctx, `SELECT identity_id FROM control.team_memberships WHERE id=$1 AND team_id=$2`, owner.membership, team).Scan(&identity); err != nil {
			return publisherLookupError(err, ErrServiceAccess)
		}
		var err error
		facts, err = serviceHostnameAuthority(ctx, tx, team, identity, domain, now)
		if err != nil {
			return err
		}
	}
	labels, err := controlstatedb.New(tx).ListTeamNamespaceLabels(ctx, team)
	if err != nil {
		return err
	}
	scope, membership := owner.scope, owner.membership
	if scope == NamespaceScopeMember {
		namespace := naming.MemberNamespace(facts.CanonicalDomain, facts.DomainKind == "managed", facts.ActorManagedLabel, facts.ActorMemberSlug)
		if hostname != namespace && hostnameWithin(hostname, namespace) {
			return nil
		}
	}
	if owner.local && facts.TeamKind == "personal" {
		_, direct := naming.PublicURLNamespace(naming.NamespaceFacts{
			Domain: facts.CanonicalDomain, Managed: facts.DomainKind == "managed", Mode: d.managedURLMode,
			Personal: true, TeamName: facts.TeamDisplayName, MemberSlug: facts.ActorMemberSlug, ManagedLabel: facts.ActorManagedLabel,
		})
		if direct {
			scope, membership = NamespaceScopeShared, ""
		}
	}
	return authorizeServiceHostname(facts, labels, team, membership, hostname, string(scope), d.managedURLMode)
}

func claimServiceSourceHostname(ctx context.Context, tx pgx.Tx, hostname, domain string, owner serviceSourceOwner, now time.Time) error {
	if owner.scope != NamespaceScopeMember && owner.scope != NamespaceScopeShared || owner.key == "" {
		return ErrServiceAccess
	}
	var conflict bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.service_namespace_claims
	    WHERE ($1=namespace OR right($1,length(namespace)+1)='.'||namespace OR right(namespace,length($1)+1)='.'||$1)
	      AND (local_source_key<>$2 OR membership_id IS DISTINCT FROM $3::text OR owner_team_id IS DISTINCT FROM $4::text OR domain_id<>$5))`,
		hostname, owner.key, nullableText(owner.membership), nullableText(owner.team), domain).Scan(&conflict); err != nil {
		return err
	}
	if conflict {
		return ErrServiceConflict
	}
	var claimed string
	err := tx.QueryRow(ctx, `INSERT INTO control.service_namespace_claims(namespace,local_source_key,membership_id,owner_team_id,domain_id,created_at)
	    VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(namespace) DO UPDATE SET local_source_key=EXCLUDED.local_source_key
	    WHERE control.service_namespace_claims.local_source_key=EXCLUDED.local_source_key
	      AND control.service_namespace_claims.membership_id IS NOT DISTINCT FROM EXCLUDED.membership_id
	      AND control.service_namespace_claims.owner_team_id IS NOT DISTINCT FROM EXCLUDED.owner_team_id
	      AND control.service_namespace_claims.domain_id=EXCLUDED.domain_id
	      AND control.service_namespace_claims.retired_at IS NULL RETURNING namespace`,
		hostname, owner.key, nullableText(owner.membership), nullableText(owner.team), domain, now).Scan(&claimed)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrServiceConflict
	}
	return err
}
