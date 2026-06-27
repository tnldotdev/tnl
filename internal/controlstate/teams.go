package controlstate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

var ErrTeamNotFound = errors.New("controlstate: team not found")

type Team struct {
	ID              string
	Kind            string
	DisplayName     string
	ManagedLabel    string
	DefaultDomainID string
	PolicyRevision  int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type Domain struct {
	ID                string
	Kind              string
	TeamID            string
	CanonicalDomain   string
	State             string
	AuthorityRevision int64
	CreatedAt         time.Time
	VerifiedAt        time.Time
	UpdatedAt         time.Time
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
			ID: row.ID, Kind: row.Kind, TeamID: row.TeamID.String,
			CanonicalDomain: row.CanonicalDomain, State: row.State,
			AuthorityRevision: row.AuthorityRevision, CreatedAt: row.CreatedAt.Time,
			VerifiedAt: row.VerifiedAt.Time, UpdatedAt: row.UpdatedAt.Time,
		}
	}
	return result, nil
}

func teamFromRow(
	id, kind, displayName, managedLabel string,
	defaultDomainID pgtype.Text,
	policyRevision int64,
	createdAt, updatedAt pgtype.Timestamptz,
) Team {
	return Team{
		ID: id, Kind: kind, DisplayName: displayName, ManagedLabel: managedLabel,
		DefaultDomainID: defaultDomainID.String, PolicyRevision: policyRevision,
		CreatedAt: createdAt.Time, UpdatedAt: updatedAt.Time,
	}
}
