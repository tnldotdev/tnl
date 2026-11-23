package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// finish creation only after every write and deferred constraint has completed.
// the original assertion is rechecked, not redeemed again; a retained control
// session is locked through commit using the existing parent-session boundary.
func finishServiceCreation(ctx context.Context, tx pgx.Tx, team, actor string, authorized serviceMembership, parentUntil *time.Time, clock authorizationClock) error {
	if _, err := tx.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
		return err
	}
	proof, signed := serviceActor(ctx)
	if err := recheckServiceMembership(ctx, tx, team, actor, authorized, clock); err != nil {
		return err
	}
	if !signed {
		deadline, err := controlstatedb.New(tx).CompanySubjectDeadline(ctx, controlstatedb.CompanySubjectDeadlineParams{
			TeamID: team, IdentityID: actor, SessionID: companySessionID(ctx, actor), Now: timestamptz(clock.current()),
		})
		if err != nil {
			return err
		}
		if deadline.Valid && deadline.InfinityModifier == 0 && !deadline.Time.After(clock.current()) {
			return errors.Join(ErrServiceAccess, ErrAuthorityAccess)
		}
	} else if err := validateServiceActorProof(proof, clock.current()); err != nil {
		return err
	}
	if parentUntil != nil && !parentUntil.After(clock.current()) {
		return ErrServiceAccess
	}
	return tx.Commit(ctx)
}

// reservation authorizes a point selection, not team discovery or a different
// creation engine. the ordinary create transaction owns every mutation.
func (d *Database) serviceReservationOwner(ctx context.Context, tx pgx.Tx, team, actor, name string, placement ServicePlacement, configuration *ProjectServiceConfiguration, now time.Time) (serviceSourceOwner, error) {
	if configuration == nil || configuration.Ephemeral || placement.DomainID == "" || placement.Hostname == "" ||
		placement.WorktreeKey != "" || placement.WorktreeLabel != "" || placement.SourceKey != "" {
		return serviceSourceOwner{}, ErrProjectConfigurationInvalid
	}
	facts, err := serviceHostnameAuthority(ctx, tx, team, actor, placement.DomainID, now)
	if err != nil {
		return serviceSourceOwner{}, err
	}
	return d.newServiceSourceOwner(ctx, tx, facts, team, placement.Hostname, "adhoc//"+name, true, true)
}

func reservedServiceRecord(ctx context.Context, tx pgx.Tx, row controlstatedb.ControlService, member serviceMembership, name string, placement ServicePlacement, selected serviceSourceOwner) (ServiceRecord, error) {
	if !row.Enabled || row.DeletedAt.Valid || row.GuestID.Valid || row.TeamID.String != member.teamID ||
		row.Name != name || row.DomainID.String != placement.DomainID || row.CertificateHostname != placement.Hostname ||
		row.PlacementWorktreeKey != "" || row.PlacementWorktreeLabel != "" || row.Ephemeral ||
		placement.UseSavedAddress && row.NameScope != "named/"+row.CreatedByIdentityID.String {
		return ServiceRecord{}, ErrServiceConflict
	}
	owner, err := storedServiceSourceOwner(ctx, tx, row, false)
	if err != nil {
		return ServiceRecord{}, err
	}
	if owner.local || owner.scope != selected.scope || owner.membership != selected.membership ||
		owner.team != selected.team || owner.key != selected.key {
		return ServiceRecord{}, ErrServiceConflict
	}
	if err := requireServiceManagement(ctx, tx, row, member); err != nil {
		return ServiceRecord{}, err
	}
	stored, err := controlstatedb.New(tx).GetServiceConfiguration(ctx, row.ID)
	if err != nil {
		return ServiceRecord{}, err
	}
	if stored.LocalOwned || stored.DeploymentOwned || stored.AllocationOwned || len(stored.ConfigurationCiphertext) == 0 || !stored.StorageKeyID.Valid {
		return ServiceRecord{}, ErrServiceConflict
	}
	result, err := checkedServiceRecord(row)
	result.Recovered = true
	return result, err
}
