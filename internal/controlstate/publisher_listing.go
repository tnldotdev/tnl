package controlstate

import (
	"context"
	"errors"
	"net"
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

type PublisherGrantSummary struct {
	ID, Kind, PublicURLID, DomainID, Namespace, PublicURL string
	CreatedAt                                             time.Time
	ExpiresAt, RevokedAt                                  *time.Time
}

type PublisherIdentitySummary struct {
	ID, Name, Kind, TeamID string
	CreatedAt              time.Time
	RevokedAt              *time.Time
	Grants                 []PublisherGrantSummary
}

type PublisherIdentityPage struct {
	Identities []PublisherIdentitySummary
	NextCursor string
}

func (d *Database) ListTeamPublisherIdentities(ctx context.Context, teamID, cursor string) (PublisherIdentityPage, error) {
	if !validStateText(teamID) || cursor != "" && !opaqueid.Valid(cursor, opaqueid.PublisherIdentityPrefix) {
		return PublisherIdentityPage{}, ErrPublisherIdentity
	}
	if err := d.requireOpen(); err != nil {
		return PublisherIdentityPage{}, err
	}
	queries := controlstatedb.New(d.pool)
	rows, err := queries.ListTeamPublisherIdentities(ctx, controlstatedb.ListTeamPublisherIdentitiesParams{
		TeamID: teamID, Cursor: nullableText(cursor),
	})
	if err != nil {
		return PublisherIdentityPage{}, err
	}
	page := PublisherIdentityPage{Identities: make([]PublisherIdentitySummary, 0, min(len(rows), 100))}
	indices := make(map[string]int, min(len(rows), 100))
	ids := make([]string, 0, min(len(rows), 100))
	for _, row := range rows[:min(len(rows), 100)] {
		entry := PublisherIdentitySummary{ID: row.ID, TeamID: row.TeamID, Name: row.Name,
			Kind: row.Kind, CreatedAt: row.CreatedAt.Time, Grants: []PublisherGrantSummary{}}
		if row.RevokedAt.Valid {
			entry.RevokedAt = &row.RevokedAt.Time
		}
		indices[row.ID] = len(page.Identities)
		ids = append(ids, row.ID)
		page.Identities = append(page.Identities, entry)
	}
	if len(ids) != 0 {
		grants, err := queries.ListPublisherGrantsForIdentities(ctx, ids)
		if err != nil {
			return PublisherIdentityPage{}, err
		}
		for _, grant := range grants {
			entry := &page.Identities[indices[grant.PublisherIdentityID]]
			if len(entry.Grants) >= 256 {
				return PublisherIdentityPage{}, errors.New("publisher grant listing exceeds its page bound")
			}
			item := PublisherGrantSummary{ID: grant.ID, Kind: grant.Kind,
				PublicURLID: grant.PublicURLID.String, DomainID: grant.DomainID.String,
				Namespace: grant.Namespace.String, CreatedAt: grant.CreatedAt.Time}
			if grant.CanonicalHostname != "" {
				item.PublicURL = "https://" + grant.CanonicalHostname
				if grant.PublicPort.Valid {
					item.PublicURL = net.JoinHostPort(grant.CanonicalHostname, strconv.Itoa(int(grant.PublicPort.Int32)))
				}
			}
			if grant.ExpiresAt.Valid {
				item.ExpiresAt = &grant.ExpiresAt.Time
			}
			if grant.RevokedAt.Valid {
				item.RevokedAt = &grant.RevokedAt.Time
			}
			entry.Grants = append(entry.Grants, item)
		}
	}
	if len(rows) > 100 {
		page.NextCursor = page.Identities[len(page.Identities)-1].ID
	}
	return page, nil
}
