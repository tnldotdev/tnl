package controlstate

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

var ErrDomainNotFound = errors.New("controlstate: domain not found")

type ClaimDomainRequest struct {
	IdentityID     string
	TeamID         string
	IdempotencyKey string
	RequestDigest  [32]byte
	Domain         string
	MakeDefault    bool
}

func (d *Database) ClaimTeamDomain(
	ctx context.Context,
	request ClaimDomainRequest,
	now time.Time,
) (result Domain, retErr error) {
	if !validStateText(request.IdentityID) || !validStateText(request.TeamID) ||
		!validIdempotencyKey(request.IdempotencyKey) || now.IsZero() {
		return Domain{}, ErrAuthorityInvalid
	}
	if err := d.requireOpen(); err != nil {
		return Domain{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Domain{}, fmt.Errorf("controlstate: claim team domain: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "claim team domain", &retErr)()
	queries := controlstatedb.New(tx)
	actor, err := lockTeamActor(ctx, queries, request.IdentityID, request.TeamID)
	if err != nil {
		return Domain{}, err
	}
	if TeamRole(actor.ActorRole) != TeamRoleAdmin && TeamRole(actor.ActorRole) != TeamRoleOwner {
		return Domain{}, ErrAuthorityAccess
	}
	managedDomain, err := queries.LockManagedDomainForClaim(ctx)
	if err != nil {
		return Domain{}, fmt.Errorf("controlstate: claim team domain: lock managed domain: %w", err)
	}
	canonical, _, err := naming.CustomDomain(request.Domain, managedDomain.CanonicalDomain)
	if err != nil || canonical != request.Domain {
		return Domain{}, ErrAuthorityInvalid
	}
	existing, err := queries.GetCustomDomainByIdempotency(ctx, controlstatedb.GetCustomDomainByIdempotencyParams{
		IdentityID: text(request.IdentityID), TeamID: text(request.TeamID), IdempotencyKey: text(request.IdempotencyKey),
	})
	if err == nil {
		if existing.ReleasedAt.Valid || subtle.ConstantTimeCompare(existing.ClaimRequestDigest, request.RequestDigest[:]) != 1 {
			return Domain{}, ErrAuthorityIdempotency
		}
		if err := tx.Commit(ctx); err != nil {
			return Domain{}, fmt.Errorf("controlstate: claim team domain: commit retry: %w", err)
		}
		return domainFromRow(
			existing.ID, existing.Kind, existing.TeamID.String, existing.CanonicalDomain,
			existing.DnsAuthorityReference.String, existing.State, existing.AuthorityRevision,
			existing.Nameservers, existing.CreatedAt.Time, existing.VerifiedAt.Time, existing.UpdatedAt.Time,
		), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Domain{}, fmt.Errorf("controlstate: claim team domain: read idempotent domain: %w", err)
	}
	domains, err := queries.ListCurrentDomainNames(ctx)
	if err != nil {
		return Domain{}, fmt.Errorf("controlstate: claim team domain: list current domains: %w", err)
	}
	for _, current := range domains {
		if naming.IsWithin(canonical, current) || naming.IsWithin(current, canonical) {
			return Domain{}, ErrAuthorityConflict
		}
	}
	revision, err := queries.AdvanceTeamPolicyRevision(ctx, controlstatedb.AdvanceTeamPolicyRevisionParams{
		UpdatedAt: timestamp(now), TeamID: request.TeamID,
	})
	if err != nil {
		return Domain{}, fmt.Errorf("controlstate: claim team domain: advance policy revision: %w", err)
	}
	domainID, err := opaqueid.New(opaqueid.DomainPrefix)
	if err != nil {
		return Domain{}, err
	}
	authorityReference, err := opaqueid.New(opaqueid.DNSAuthorityPrefix)
	if err != nil {
		return Domain{}, err
	}
	if err := queries.CreateCustomDNSAuthority(ctx, controlstatedb.CreateCustomDNSAuthorityParams{
		AuthorityReference: authorityReference, TeamID: request.TeamID, DomainID: domainID,
		CanonicalDomain: canonical, CreateIdempotencyKey: "self_hosted_" + domainID,
		CreateRequestDigest: request.RequestDigest[:], CreatedAt: timestamp(now),
	}); err != nil {
		return Domain{}, fmt.Errorf("controlstate: claim team domain: create DNS authority: %w", err)
	}
	row, err := queries.CreateCustomDomain(ctx, controlstatedb.CreateCustomDomainParams{
		ID: domainID, TeamID: text(request.TeamID), CanonicalDomain: canonical,
		DnsAuthorityReference: text(authorityReference), AuthorityRevision: revision,
		CreatedByIdentityID: text(request.IdentityID), ClaimIdempotencyKey: text(request.IdempotencyKey),
		ClaimRequestDigest: request.RequestDigest[:], MakeDefaultWhenReady: request.MakeDefault,
		CreatedAt: timestamp(now),
	})
	if err != nil {
		if isUniqueViolation(err) {
			return Domain{}, ErrAuthorityConflict
		}
		return Domain{}, fmt.Errorf("controlstate: claim team domain: insert domain: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Domain{}, fmt.Errorf("controlstate: claim team domain: commit: %w", err)
	}
	return domainFromRow(
		row.ID, row.Kind, row.TeamID.String, row.CanonicalDomain, row.DnsAuthorityReference.String,
		row.State, row.AuthorityRevision, nil, row.CreatedAt.Time, row.VerifiedAt.Time, row.UpdatedAt.Time,
	), nil
}

func (d *Database) SetTeamDefaultDomain(
	ctx context.Context,
	identityID, teamID, domainID string,
	now time.Time,
) (result Team, retErr error) {
	if !validStateText(identityID) || !validStateText(teamID) || !validStateText(domainID) || now.IsZero() {
		return Team{}, ErrAuthorityInvalid
	}
	if err := d.requireOpen(); err != nil {
		return Team{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Team{}, fmt.Errorf("controlstate: set team default domain: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "set team default domain", &retErr)()
	queries := controlstatedb.New(tx)
	actor, err := lockTeamActor(ctx, queries, identityID, teamID)
	if err != nil {
		return Team{}, err
	}
	if TeamRole(actor.ActorRole) != TeamRoleAdmin && TeamRole(actor.ActorRole) != TeamRoleOwner {
		return Team{}, ErrAuthorityAccess
	}
	domain, err := queries.LockTeamDomain(ctx, controlstatedb.LockTeamDomainParams{
		DomainID: domainID, TeamID: text(teamID),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Team{}, ErrDomainNotFound
	}
	if err != nil {
		return Team{}, fmt.Errorf("controlstate: set team default domain: lock domain: %w", err)
	}
	if DomainState(domain.State) != DomainReady {
		return Team{}, ErrAuthorityConflict
	}
	if actor.DefaultDomainID.String != domainID {
		updated, err := queries.SetTeamDefaultDomain(ctx, controlstatedb.SetTeamDefaultDomainParams{
			DomainID: text(domainID), UpdatedAt: timestamp(now), TeamID: teamID,
		})
		if err != nil {
			return Team{}, fmt.Errorf("controlstate: set team default domain: update team: %w", err)
		}
		if updated != 1 {
			return Team{}, ErrTeamNotFound
		}
	}
	row, err := queries.GetIdentityTeam(ctx, controlstatedb.GetIdentityTeamParams{IdentityID: identityID, TeamID: teamID})
	if err != nil {
		return Team{}, fmt.Errorf("controlstate: set team default domain: read result: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Team{}, fmt.Errorf("controlstate: set team default domain: commit: %w", err)
	}
	return teamFromRow(
		row.ID, row.Kind, row.DisplayName, row.ManagedLabel, row.DefaultDomainID,
		row.PolicyRevision, row.CreatedAt, row.UpdatedAt,
	), nil
}

func (d *Database) ReleaseTeamDomain(
	ctx context.Context,
	identityID, teamID, domainID string,
	now time.Time,
) (retErr error) {
	if !validStateText(identityID) || !validStateText(teamID) || !validStateText(domainID) || now.IsZero() {
		return ErrAuthorityInvalid
	}
	if err := d.requireOpen(); err != nil {
		return err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("controlstate: release team domain: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "release team domain", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	actor, err := lockTeamActor(ctx, queries, identityID, teamID)
	if err != nil {
		return err
	}
	if TeamRole(actor.ActorRole) != TeamRoleOwner {
		return ErrAuthorityAccess
	}
	domain, err := queries.LockTeamDomain(ctx, controlstatedb.LockTeamDomainParams{
		DomainID: domainID, TeamID: text(teamID),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrDomainNotFound
	}
	if err != nil {
		return fmt.Errorf("controlstate: release team domain: lock domain: %w", err)
	}
	if DomainKind(domain.Kind) != DomainKindCustom || domain.TeamID.String != teamID {
		return ErrAuthorityAccess
	}
	if actor.DefaultDomainID.String == domainID {
		return ErrAuthorityConflict
	}
	if DomainState(domain.State) == DomainReleasing {
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("controlstate: release team domain: commit replay: %w", err)
		}
		return nil
	}
	revision, err := queries.AdvanceTeamPolicyRevision(ctx, controlstatedb.AdvanceTeamPolicyRevisionParams{
		UpdatedAt: timestamp(now), TeamID: teamID,
	})
	if err != nil {
		return fmt.Errorf("controlstate: release team domain: advance policy revision: %w", err)
	}
	updated, err := queries.MarkCustomDomainReleasing(ctx, controlstatedb.MarkCustomDomainReleasingParams{
		AuthorityRevision: revision, UpdatedAt: timestamp(now), DomainID: domainID, TeamID: text(teamID),
	})
	if err != nil {
		return fmt.Errorf("controlstate: release team domain: update domain: %w", err)
	}
	if updated != 1 {
		return ErrAuthorityConflict
	}
	if !domain.DnsAuthorityReference.Valid {
		return ErrAuthorityConflict
	}
	updated, err = queries.MarkDNSAuthorityReleasing(ctx, controlstatedb.MarkDNSAuthorityReleasingParams{
		UpdatedAt: timestamp(now), AuthorityReference: domain.DnsAuthorityReference.String,
	})
	if err != nil {
		return fmt.Errorf("controlstate: release team domain: update DNS authority: %w", err)
	}
	if updated != 1 {
		return ErrAuthorityConflict
	}
	routes, err := queries.LockDomainPublicURLs(ctx, controlstatedb.LockDomainPublicURLsParams{TeamID: teamID, DomainID: domainID})
	if err != nil {
		return fmt.Errorf("controlstate: release team domain: lock public_urls: %w", err)
	}
	for _, route := range routes {
		if err := closeOpenPublishRun(ctx, queries, &pendingEvents, route, now, "domain_releasing"); err != nil {
			return err
		}
		updated, err := queries.SuspendAuthorityPublicURL(ctx, controlstatedb.SuspendAuthorityPublicURLParams{
			SuspensionReason: text("domain_releasing"), SuspendedAt: timestamptz(now), PublicURLID: route.ID,
		})
		if err != nil {
			return fmt.Errorf("controlstate: release team domain: suspend public_url: %w", err)
		}
		if updated != 1 {
			return ErrAuthorityConflict
		}
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("controlstate: release team domain: commit: %w", err)
	}
	return nil
}

func domainFromRow(
	id, kind, teamID, canonicalDomain, authorityReference, state string,
	authorityRevision int64,
	nameservers []string,
	createdAt, verifiedAt, updatedAt time.Time,
) Domain {
	return Domain{
		ID: id, Kind: DomainKind(kind), TeamID: teamID, CanonicalDomain: canonicalDomain,
		DNSAuthorityReference: authorityReference, State: DomainState(state), AuthorityRevision: authorityRevision,
		RequiredRecords: nameserverRecords(canonicalDomain, nameservers), CreatedAt: createdAt,
		VerifiedAt: verifiedAt, UpdatedAt: updatedAt,
	}
}
