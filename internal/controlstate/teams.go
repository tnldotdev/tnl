package controlstate

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

var (
	ErrAuthorityAccess      = errors.New("controlstate: authority access denied")
	ErrAuthorityConflict    = errors.New("controlstate: authority state conflict")
	ErrAuthorityIdempotency = errors.New("controlstate: authority idempotency conflict")
	ErrAuthorityInvalid     = errors.New("controlstate: authority request is invalid")
	ErrMembershipNotFound   = errors.New("controlstate: membership not found")
	ErrTeamNotFound         = errors.New("controlstate: team not found")
	ErrTeamNameUnavailable  = errors.New("controlstate: team name unavailable")
	ErrMemberSlugRequired   = errors.New("controlstate: member slug required")
)

type Team struct {
	ID              string
	Kind            TeamKind
	DisplayName     string
	ManagedLabel    string
	DefaultDomainID string
	PolicyRevision  int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type Domain struct {
	ID                    string
	Kind                  DomainKind
	TeamID                string
	CanonicalDomain       string
	DNSAuthorityReference string
	State                 DomainState
	AuthorityRevision     int64
	RequiredRecords       []DNSRecord
	CreatedAt             time.Time
	VerifiedAt            time.Time
	UpdatedAt             time.Time
}

type DNSRecord struct {
	Name  string
	Type  string
	Value string
}

type CreateTeamRequest struct {
	IdentityID     string
	IdempotencyKey string
	RequestDigest  [32]byte
	DisplayName    string
	MemberSlug     string
}

func (d *Database) CreateTeam(ctx context.Context, request CreateTeamRequest, now time.Time) (result Team, retErr error) {
	if !validStateText(request.IdentityID) || !validIdempotencyKey(request.IdempotencyKey) ||
		!naming.ValidAuthorityLabel(request.DisplayName) ||
		(request.MemberSlug != "" && !naming.ValidAuthorityLabel(request.MemberSlug)) || now.IsZero() {
		return Team{}, ErrAuthorityInvalid
	}
	if err := d.requireOpen(); err != nil {
		return Team{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Team{}, fmt.Errorf("controlstate: create team: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "create team", &retErr)()
	queries := controlstatedb.New(tx)
	identity, err := queries.LockIdentityForTeamCreation(ctx, request.IdentityID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Team{}, ErrAuthorityAccess
	} else if err != nil {
		return Team{}, fmt.Errorf("controlstate: create team: lock identity: %w", err)
	}
	existing, err := queries.GetOrganizationTeamByIdempotency(ctx, controlstatedb.GetOrganizationTeamByIdempotencyParams{
		IdentityID: request.IdentityID, IdempotencyKey: text(request.IdempotencyKey),
	})
	if err == nil {
		if subtle.ConstantTimeCompare(existing.CreationRequestDigest, request.RequestDigest[:]) != 1 {
			return Team{}, ErrAuthorityIdempotency
		}
		if err := tx.Commit(ctx); err != nil {
			return Team{}, fmt.Errorf("controlstate: create team: commit retry: %w", err)
		}
		return teamFromRow(
			existing.ID, existing.Kind, existing.DisplayName, existing.ManagedLabel, existing.DefaultDomainID,
			existing.PolicyRevision, existing.CreatedAt, existing.UpdatedAt,
		), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Team{}, fmt.Errorf("controlstate: create team: read idempotent team: %w", err)
	}
	memberSlug := request.MemberSlug
	if memberSlug == "" {
		memberSlug = naming.MemberSlugFromDisplayName(identity.DisplayName)
		if !naming.ValidAuthorityLabel(memberSlug) {
			return Team{}, ErrMemberSlugRequired
		}
	}
	managedDomain, err := queries.FindManagedDomain(ctx)
	if err != nil {
		return Team{}, fmt.Errorf("controlstate: create team: read managed domain: %w", err)
	}
	// reserve the team name against personal teams and managed-domain names.
	if _, err := queries.ReserveManagedLabel(ctx, controlstatedb.ReserveManagedLabelParams{
		Label: request.DisplayName, CreatedAt: timestamp(now),
	}); errors.Is(err, pgx.ErrNoRows) {
		return Team{}, ErrTeamNameUnavailable
	} else if err != nil {
		return Team{}, fmt.Errorf("controlstate: create team: reserve name label: %w", err)
	}
	if reserved, err := queries.GuestNamespaceReserved(ctx, request.DisplayName); err != nil {
		return Team{}, err
	} else if reserved {
		return Team{}, ErrTeamNameUnavailable
	}
	managedLabel := request.DisplayName
	if d.managedURLMode == naming.ManagedURLModeGenerated {
		managedLabel, err = availableManagedLabel(ctx, queries, now)
		if err != nil {
			return Team{}, err
		}
	}
	teamID, err := opaqueid.New(opaqueid.TeamPrefix)
	if err != nil {
		return Team{}, err
	}
	reservationID, err := opaqueid.New(opaqueid.SlugReservationPrefix)
	if err != nil {
		return Team{}, err
	}
	membershipID, err := opaqueid.New(opaqueid.MembershipPrefix)
	if err != nil {
		return Team{}, err
	}
	createdAt := timestamp(now)
	row, err := queries.CreateOrganizationTeam(ctx, controlstatedb.CreateOrganizationTeamParams{
		ID: teamID, DisplayName: request.DisplayName, ManagedLabel: managedLabel,
		DefaultDomainID: text(managedDomain.ID), CreatedByIdentityID: request.IdentityID,
		CreationIdempotencyKey: text(request.IdempotencyKey), CreationRequestDigest: request.RequestDigest[:],
		CreatedAt: createdAt,
	})
	if err != nil {
		var duplicate *pgconn.PgError
		if errors.As(err, &duplicate) && duplicate.ConstraintName == "teams_name_unique" {
			return Team{}, fmt.Errorf("team name %q is already taken: %w", request.DisplayName, ErrTeamNameUnavailable)
		}
		return Team{}, fmt.Errorf("controlstate: create team: insert team: %w", err)
	}
	if err := queries.CreateActiveSlugReservation(ctx, controlstatedb.CreateActiveSlugReservationParams{
		ID: reservationID, TeamID: teamID, MemberSlug: memberSlug,
		IdentityID: text(request.IdentityID), CreatedAt: createdAt,
	}); err != nil {
		return Team{}, fmt.Errorf("controlstate: create team: reserve creator slug: %w", err)
	}
	if err := queries.CreateOwnerMembership(ctx, controlstatedb.CreateOwnerMembershipParams{
		ID: membershipID, TeamID: teamID, IdentityID: request.IdentityID,
		SlugReservationID: reservationID, ManagedLabel: managedLabel, CreatedAt: createdAt,
	}); err != nil {
		return Team{}, fmt.Errorf("controlstate: create team: create owner membership: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Team{}, fmt.Errorf("controlstate: create team: commit: %w", err)
	}
	return teamFromRow(
		row.ID, row.Kind, row.DisplayName, row.ManagedLabel, row.DefaultDomainID,
		row.PolicyRevision, row.CreatedAt, row.UpdatedAt,
	), nil
}

func (d *Database) ListTeams(ctx context.Context, identityID string) ([]Team, error) {
	rows, err := controlstatedb.New(d.pool).ListIdentityTeams(ctx, identityID)
	if err != nil {
		return nil, fmt.Errorf("controlstate: list teams: %w", err)
	}
	result := make([]Team, len(rows))
	for index, row := range rows {
		result[index] = teamFromRow(
			row.ID, row.Kind, row.DisplayName, row.ManagedLabel, row.DefaultDomainID,
			row.PolicyRevision, row.CreatedAt, row.UpdatedAt,
		)
	}
	return result, nil
}

func (d *Database) GetTeam(ctx context.Context, identityID, teamID string) (Team, error) {
	row, err := controlstatedb.New(d.pool).GetIdentityTeam(ctx, controlstatedb.GetIdentityTeamParams{
		IdentityID: identityID, TeamID: teamID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Team{}, ErrTeamNotFound
	}
	if err != nil {
		return Team{}, fmt.Errorf("controlstate: get team: %w", err)
	}
	return teamFromRow(
		row.ID, row.Kind, row.DisplayName, row.ManagedLabel, row.DefaultDomainID,
		row.PolicyRevision, row.CreatedAt, row.UpdatedAt,
	), nil
}

func (d *Database) ListTeamMemberships(ctx context.Context, identityID, teamID string) ([]Membership, error) {
	if !validStateText(identityID) || !validStateText(teamID) {
		return nil, ErrAuthorityInvalid
	}
	queries := controlstatedb.New(d.pool)
	if _, err := queries.GetTeamActorContext(ctx, controlstatedb.GetTeamActorContextParams{
		IdentityID: identityID, TeamID: teamID,
	}); errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTeamNotFound
	} else if err != nil {
		return nil, fmt.Errorf("controlstate: list team memberships: read actor: %w", err)
	}
	rows, err := queries.ListTeamMembershipContexts(ctx, controlstatedb.ListTeamMembershipContextsParams{
		TeamID: teamID, IdentityID: identityID,
	})
	if err != nil {
		return nil, fmt.Errorf("controlstate: list team memberships: %w", err)
	}
	// an actor may be removed after the first lookup. the list query checks
	// authorization in its own snapshot; an authorized actor has a row there.
	if len(rows) == 0 {
		return nil, ErrTeamNotFound
	}
	result := make([]Membership, len(rows))
	for index, row := range rows {
		result[index] = membershipFromRow(
			row.ID, row.TeamID, row.IdentityID, row.TeamDisplayName, row.TeamKind, row.Role,
			row.MemberSlug, row.ManagedLabel, row.PolicyRevision, row.CreatedAt, row.UpdatedAt,
		)
	}
	return result, nil
}

func (d *Database) SetMembershipRole(
	ctx context.Context,
	identityID, teamID, membershipID string,
	role TeamRole,
	now time.Time,
) (result Membership, retErr error) {
	if !validStateText(identityID) || !validStateText(teamID) || !validStateText(membershipID) ||
		!role.valid() || now.IsZero() {
		return Membership{}, ErrAuthorityInvalid
	}
	if err := d.requireOpen(); err != nil {
		return Membership{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Membership{}, fmt.Errorf("controlstate: set membership role: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "set membership role", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	actor, err := lockTeamActor(ctx, queries, identityID, teamID)
	if err != nil {
		return Membership{}, err
	}
	if TeamKind(actor.Kind) != TeamKindOrganization || TeamRole(actor.ActorRole) != TeamRoleOwner {
		return Membership{}, ErrAuthorityAccess
	}
	target, err := queries.LockTeamMembership(ctx, controlstatedb.LockTeamMembershipParams{
		MembershipID: membershipID, TeamID: teamID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Membership{}, ErrMembershipNotFound
	}
	if err != nil {
		return Membership{}, fmt.Errorf("controlstate: set membership role: lock membership: %w", err)
	}
	targetRole := TeamRole(target.Role)
	if targetRole == role {
		if err := tx.Commit(ctx); err != nil {
			return Membership{}, fmt.Errorf("controlstate: set membership role: commit no-op: %w", err)
		}
		return d.getMembership(ctx, teamID, membershipID)
	}
	if targetRole == TeamRoleOwner {
		owners, err := queries.CountTeamOwners(ctx, teamID)
		if err != nil {
			return Membership{}, fmt.Errorf("controlstate: set membership role: count owners: %w", err)
		}
		if owners == 1 {
			return Membership{}, ErrAuthorityConflict
		}
	}
	revision, err := queries.AdvanceTeamPolicyRevision(ctx, controlstatedb.AdvanceTeamPolicyRevisionParams{
		UpdatedAt: timestamp(now), TeamID: teamID,
	})
	if err != nil {
		return Membership{}, fmt.Errorf("controlstate: set membership role: advance policy revision: %w", err)
	}
	if updated, err := queries.UpdateMembershipRole(ctx, controlstatedb.UpdateMembershipRoleParams{
		Role: string(role), AuthorityRevision: revision, UpdatedAt: timestamp(now), MembershipID: membershipID, TeamID: teamID,
	}); err != nil || updated != 1 {
		return Membership{}, authorityRowsError("set membership role: update membership", updated, err)
	}
	if err := closeMembershipPublishRuns(ctx, queries, &pendingEvents, teamID, membershipID, false, now, "authority_policy_changed"); err != nil {
		return Membership{}, err
	}
	row, err := queries.GetTeamMembershipContext(ctx, controlstatedb.GetTeamMembershipContextParams{
		MembershipID: membershipID, TeamID: teamID,
	})
	if err != nil {
		return Membership{}, fmt.Errorf("controlstate: set membership role: read result: %w", err)
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return Membership{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Membership{}, fmt.Errorf("controlstate: set membership role: commit: %w", err)
	}
	return membershipFromRow(
		row.ID, row.TeamID, row.IdentityID, row.TeamDisplayName, row.TeamKind, row.Role,
		row.MemberSlug, row.ManagedLabel, row.PolicyRevision, row.CreatedAt, row.UpdatedAt,
	), nil
}

func (d *Database) RemoveMembership(
	ctx context.Context,
	identityID, teamID, membershipID string,
	now time.Time,
) (retErr error) {
	if !validStateText(identityID) || !validStateText(teamID) || !validStateText(membershipID) || now.IsZero() {
		return ErrAuthorityInvalid
	}
	if err := d.requireOpen(); err != nil {
		return err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return fmt.Errorf("controlstate: remove membership: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "remove membership", &retErr)()
	queries := controlstatedb.New(tx)
	pendingEvents := pendingIngressRoutingTableEvents{}
	actor, err := lockTeamActor(ctx, queries, identityID, teamID)
	if err != nil {
		return err
	}
	actorRole := TeamRole(actor.ActorRole)
	if TeamKind(actor.Kind) != TeamKindOrganization || actorRole != TeamRoleOwner && actorRole != TeamRoleAdmin {
		return ErrAuthorityAccess
	}
	target, err := queries.LockTeamMembership(ctx, controlstatedb.LockTeamMembershipParams{
		MembershipID: membershipID, TeamID: teamID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrMembershipNotFound
	}
	if err != nil {
		return fmt.Errorf("controlstate: remove membership: lock membership: %w", err)
	}
	targetRole := TeamRole(target.Role)
	if actorRole == TeamRoleAdmin && targetRole != TeamRoleMember {
		return ErrAuthorityAccess
	}
	if targetRole == TeamRoleOwner {
		owners, err := queries.CountTeamOwners(ctx, teamID)
		if err != nil {
			return fmt.Errorf("controlstate: remove membership: count owners: %w", err)
		}
		if owners == 1 {
			return ErrAuthorityConflict
		}
	}
	revision, err := queries.AdvanceTeamPolicyRevision(ctx, controlstatedb.AdvanceTeamPolicyRevisionParams{
		UpdatedAt: timestamp(now), TeamID: teamID,
	})
	if err != nil {
		return fmt.Errorf("controlstate: remove membership: advance policy revision: %w", err)
	}
	if updated, err := queries.RemoveTeamMembership(ctx, controlstatedb.RemoveTeamMembershipParams{
		AuthorityRevision: revision, RemovedAt: timestamp(now), RemovedByIdentityID: text(identityID),
		MembershipID: membershipID, TeamID: teamID,
	}); err != nil || updated != 1 {
		return authorityRowsError("remove membership: update membership", updated, err)
	}
	if updated, err := queries.QuarantineMemberSlug(ctx, controlstatedb.QuarantineMemberSlugParams{
		QuarantinedAt: timestamp(now), SlugReservationID: target.SlugReservationID,
	}); err != nil || updated != 1 {
		return authorityRowsError("remove membership: quarantine slug", updated, err)
	}
	if err := closeMembershipPublishRuns(ctx, queries, &pendingEvents, teamID, membershipID, true, now, "membership_removed"); err != nil {
		return err
	}
	if err := pendingEvents.publish(ctx, queries); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("controlstate: remove membership: commit: %w", err)
	}
	return nil
}

func (d *Database) ListTeamDomains(ctx context.Context, identityID, teamID string) ([]Domain, error) {
	rows, err := controlstatedb.New(d.pool).ListIdentityTeamDomains(ctx, controlstatedb.ListIdentityTeamDomainsParams{
		TeamID: text(teamID), IdentityID: identityID,
	})
	if err != nil {
		return nil, fmt.Errorf("controlstate: list team domains: %w", err)
	}
	if len(rows) == 0 {
		if _, err := d.GetTeam(ctx, identityID, teamID); err != nil {
			return nil, err
		}
	}
	result := make([]Domain, len(rows))
	for index, row := range rows {
		result[index] = Domain{
			ID: row.ID, Kind: DomainKind(row.Kind), TeamID: row.TeamID.String,
			CanonicalDomain: row.CanonicalDomain, DNSAuthorityReference: row.DnsAuthorityReference.String, State: DomainState(row.State),
			AuthorityRevision: row.AuthorityRevision, RequiredRecords: nameserverRecords(row.CanonicalDomain, row.Nameservers),
			CreatedAt:  row.CreatedAt.Time,
			VerifiedAt: row.VerifiedAt.Time, UpdatedAt: row.UpdatedAt.Time,
		}
	}
	return result, nil
}

func (d *Database) getMembership(ctx context.Context, teamID, membershipID string) (Membership, error) {
	row, err := controlstatedb.New(d.pool).GetTeamMembershipContext(ctx, controlstatedb.GetTeamMembershipContextParams{
		MembershipID: membershipID, TeamID: teamID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Membership{}, ErrMembershipNotFound
	}
	if err != nil {
		return Membership{}, fmt.Errorf("controlstate: get membership: %w", err)
	}
	return membershipFromRow(
		row.ID, row.TeamID, row.IdentityID, row.TeamDisplayName, row.TeamKind, row.Role,
		row.MemberSlug, row.ManagedLabel, row.PolicyRevision, row.CreatedAt, row.UpdatedAt,
	), nil
}

func lockTeamActor(
	ctx context.Context,
	queries *controlstatedb.Queries,
	identityID, teamID string,
) (controlstatedb.LockTeamActorContextRow, error) {
	if _, err := queries.LockLocalTeamForMutation(ctx, teamID); errors.Is(err, pgx.ErrNoRows) {
		return controlstatedb.LockTeamActorContextRow{}, ErrTeamNotFound
	} else if err != nil {
		return controlstatedb.LockTeamActorContextRow{}, fmt.Errorf("controlstate: lock team: %w", err)
	}
	row, err := queries.LockTeamActorContext(ctx, controlstatedb.LockTeamActorContextParams{
		IdentityID: identityID, TeamID: teamID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return controlstatedb.LockTeamActorContextRow{}, ErrTeamNotFound
	}
	if err != nil {
		return controlstatedb.LockTeamActorContextRow{}, fmt.Errorf("controlstate: lock team actor: %w", err)
	}
	return row, nil
}

func closeMembershipPublishRuns(
	ctx context.Context,
	queries *controlstatedb.Queries,
	pendingEvents *pendingIngressRoutingTableEvents,
	teamID, membershipID string,
	suspendMemberPublicURLs bool,
	now time.Time,
	reason string,
) error {
	routes, err := queries.LockMembershipPublicURLs(ctx, controlstatedb.LockMembershipPublicURLsParams{
		TeamID: teamID, MembershipID: text(membershipID),
	})
	if err != nil {
		return fmt.Errorf("controlstate: update membership public_urls: lock public_urls: %w", err)
	}
	for _, route := range routes {
		session, err := queries.GetOpenPublishRun(ctx, route.ID)
		if err == nil && (route.MembershipID.String == membershipID || session.MembershipID.String == membershipID) {
			if err := closePublishRun(ctx, queries, pendingEvents, route, session, PublishRunClosed, now, reason); err != nil {
				return err
			}
		} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("controlstate: update membership public_urls: read publish run: %w", err)
		}
		if suspendMemberPublicURLs && route.MembershipID.Valid && route.MembershipID.String == membershipID {
			if updated, err := queries.SuspendAuthorityPublicURL(ctx, controlstatedb.SuspendAuthorityPublicURLParams{
				SuspensionReason: text(reason), SuspendedAt: timestamptz(now), PublicURLID: route.ID,
			}); err != nil || updated != 1 {
				return authorityRowsError("update membership public_urls: suspend route", updated, err)
			}
		}
	}
	return nil
}

func membershipFromRow(
	id, teamID, identityID, teamDisplayName, teamKind, role, memberSlug, managedLabel string,
	policyRevision int64,
	createdAt, updatedAt pgtype.Timestamptz,
) Membership {
	return Membership{
		ID: id, TeamID: teamID, IdentityID: identityID, TeamDisplayName: teamDisplayName,
		TeamKind: TeamKind(teamKind), Role: TeamRole(role), MemberSlug: memberSlug, ManagedLabel: managedLabel,
		PolicyRevision: policyRevision, CreatedAt: createdAt.Time, UpdatedAt: updatedAt.Time,
	}
}

func nameserverRecords(domain string, nameservers []string) []DNSRecord {
	records := make([]DNSRecord, len(nameservers))
	for index, nameserver := range nameservers {
		records[index] = DNSRecord{Name: domain, Type: "NS", Value: nameserver}
	}
	return records
}

func validIdempotencyKey(value string) bool {
	return validStateText(value) && len(value) <= 128
}

func teamFromRow(
	id, kind, displayName, managedLabel string,
	defaultDomainID pgtype.Text,
	policyRevision int64,
	createdAt, updatedAt pgtype.Timestamptz,
) Team {
	return Team{
		ID: id, Kind: TeamKind(kind), DisplayName: displayName, ManagedLabel: managedLabel,
		DefaultDomainID: defaultDomainID.String, PolicyRevision: policyRevision,
		CreatedAt: createdAt.Time, UpdatedAt: updatedAt.Time,
	}
}
