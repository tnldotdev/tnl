package state

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

// DomainRelease is an owner observation, never a release completion estimate.
type DomainRelease struct {
	ObservedAt           time.Time
	Blockers             []string
	CertificateExpiresAt *time.Time
	CompletionUnknown    bool
	ReleasedAt           *time.Time
}

// GetTeamDomain includes final release history without making it selectable.
// membership, domain ownership, and all release facts share one query snapshot.
func (d *Database) GetTeamDomain(ctx context.Context, identityID, teamID, domainID string, now time.Time) (Domain, error) {
	if !validStateText(identityID) || !validStateText(teamID) || !validStateText(domainID) || now.IsZero() {
		return Domain{}, ErrAuthorityInvalid
	}
	if err := d.requireOpen(); err != nil {
		return Domain{}, err
	}
	row, err := controlstatedb.New(d.pool).GetIdentityTeamDomainRelease(ctx, controlstatedb.GetIdentityTeamDomainReleaseParams{
		IdentityID: identityID, TeamID: text(teamID), DomainID: domainID, ObservedAt: timestamp(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Domain{}, ErrDomainNotFound
	}
	if err != nil {
		return Domain{}, fmt.Errorf("controlstate: read team domain release facts: %w", err)
	}
	domain := domainFromRow(row.ID, row.Kind, row.TeamID.String, row.CanonicalDomain,
		row.DnsAuthorityReference.String, row.State, row.AuthorityRevision, row.Nameservers,
		row.CreatedAt.Time, row.VerifiedAt.Time, row.UpdatedAt.Time)
	if domain.Kind == DomainKindCustom && (domain.State == DomainReleasing || domain.State == DomainReleased) {
		domain.Release = &DomainRelease{ObservedAt: row.ObservedAt.Time,
			Blockers: slices.Clone(row.ReleaseBlockers), CompletionUnknown: domain.State != DomainReleased}
		if row.CertificateExpiresAt.Valid {
			domain.Release.CertificateExpiresAt = &row.CertificateExpiresAt.Time
		}
		if domain.State == DomainReleased {
			if !row.ReleasedAt.Valid {
				return Domain{}, errors.New("controlstate: released domain lacks owner confirmation")
			}
			domain.Release.ReleasedAt = &row.ReleasedAt.Time
		}
	}
	return domain, nil
}
