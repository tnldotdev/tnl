package controlstate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// HumanAuthenticationSeeds are explicit identities at one exact configured
// issuer. each privilege seed is applied once, never reconciled on restart.
type HumanAuthenticationSeeds struct {
	Issuer             string
	Administrators     []string
	TeamOwners         map[string]string
	DefaultTeam        string
	DefaultTeamMembers []string
}

func (d *Database) SeedHumanAuthentication(ctx context.Context, domain string, seeds HumanAuthenticationSeeds, now time.Time) error {
	resolve := func(subject string) (IdentityContext, error) {
		if !validStateText(seeds.Issuer) || !validStateText(subject) || len(subject) > 256 {
			return IdentityContext{}, ErrAuthorityInvalid
		}
		identity, err := d.EnsureServiceIdentity(ctx, domain, OIDCIdentity{Issuer: seeds.Issuer, Subject: subject, DisplayName: subject}, now)
		if errors.Is(err, ErrAuthorityAccess) {
			return IdentityContext{}, nil
		}
		return identity, err
	}
	for _, subject := range seeds.Administrators {
		identity, err := resolve(subject)
		if err != nil {
			return err
		}
		if identity.Identity.ID == "" {
			continue
		}
		key, _ := json.Marshal([]string{"administrator", seeds.Issuer, subject})
		if err := controlstatedb.New(d.pool).SeedAdministrator(ctx, controlstatedb.SeedAdministratorParams{SeedKey: string(key), AppliedAt: timestamptz(now), IdentityID: identity.Identity.ID}); err != nil {
			return err
		}
	}
	for team, subject := range seeds.TeamOwners {
		if !naming.ValidAuthorityLabel(team) {
			return ErrAuthorityInvalid
		}
		identity, err := resolve(subject)
		if err != nil {
			return err
		}
		if identity.Identity.ID == "" {
			continue
		}
		key, _ := json.Marshal([]string{"team-owner", seeds.Issuer, subject, team})
		digest := sha256.Sum256(key)
		if _, err := d.CreateTeam(ctx, CreateTeamRequest{IdentityID: identity.Identity.ID, DisplayName: team, MemberSlug: "owner", IdempotencyKey: "oidc-seed-" + hex.EncodeToString(digest[:]), RequestDigest: digest}, now); err != nil {
			return err
		}
	}
	if seeds.DefaultTeam == "" {
		if len(seeds.DefaultTeamMembers) > 0 {
			return ErrAuthorityInvalid
		}
		return nil
	}
	for _, subject := range seeds.DefaultTeamMembers {
		identity, err := resolve(subject)
		if err != nil {
			return err
		}
		if identity.Identity.ID == "" {
			continue
		}
		if err := d.seedDefaultTeamMember(ctx, seeds, subject, identity, now); err != nil {
			return err
		}
	}
	return nil
}

func (d *Database) seedDefaultTeamMember(ctx context.Context, seeds HumanAuthenticationSeeds, subject string, identity IdentityContext, now time.Time) (retErr error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(ctx, tx, "seed default team", &retErr)()
	q := controlstatedb.New(tx)
	if err := q.LockIdentityBootstrap(ctx); err != nil {
		return err
	}
	key, _ := json.Marshal([]string{"default-team", seeds.Issuer, subject, seeds.DefaultTeam})
	inserted, err := q.ConsumeAuthenticationSeed(ctx, controlstatedb.ConsumeAuthenticationSeedParams{SeedKey: string(key), AppliedAt: timestamptz(now)})
	if err != nil {
		return err
	}
	if inserted == 0 {
		return tx.Commit(ctx)
	}
	team, err := q.FindSeedTeam(ctx, seeds.DefaultTeam)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrTeamNotFound
	}
	if err != nil {
		return err
	}
	var exists bool
	for _, member := range identity.Memberships {
		if member.TeamID == team.ID {
			exists = true
		}
	}
	if !exists {
		// never resurrect a removed membership, even if it predates this seed.
		history, err := q.HasTeamMembershipHistory(ctx, controlstatedb.HasTeamMembershipHistoryParams{TeamID: team.ID, IdentityID: identity.Identity.ID})
		if err != nil {
			return err
		}
		if history {
			return tx.Commit(ctx)
		}
		reservation, err := opaqueid.New(opaqueid.SlugReservationPrefix)
		if err != nil {
			return err
		}
		membership, err := opaqueid.New(opaqueid.MembershipPrefix)
		if err != nil {
			return err
		}
		label, err := availableManagedLabel(ctx, q, now)
		if err != nil {
			return err
		}
		if err := q.CreateActiveSlugReservation(ctx, controlstatedb.CreateActiveSlugReservationParams{ID: reservation, TeamID: team.ID, MemberSlug: label, IdentityID: text(identity.Identity.ID), CreatedAt: timestamptz(now)}); err != nil {
			return err
		}
		if err := q.CreateSeedMember(ctx, controlstatedb.CreateSeedMemberParams{ID: membership, TeamID: team.ID, IdentityID: identity.Identity.ID, SlugReservationID: reservation, ManagedLabel: label, CreatedAt: timestamptz(now)}); err != nil {
			return err
		}
	}
	if err := q.SetIdentityInitialTeam(ctx, controlstatedb.SetIdentityInitialTeamParams{IdentityID: identity.Identity.ID, TeamID: text(team.ID)}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
