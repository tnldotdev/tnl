package controlstate

import (
	"context"
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

// AvailablePublicURL contains only the fields a visitor needs to identify a
// saved public URL. inventory visibility does not grant publication authority.
type AvailablePublicURL struct {
	ID                string
	TeamID            string
	TeamName          string
	CanonicalHostname string
	ServiceProtocol   PublicURLServiceProtocol
	PublicPort        *uint16
	PublicURLScope    PublicURLScope
	Purpose           PublicURLPurpose
	LifecycleState    PublicURLLifecycleState
	VisitorAccess     string
}

type AvailablePublicURLPage struct {
	PublicURLs []AvailablePublicURL
	NextCursor string
}

func (d *Database) ListAvailablePublicURLs(ctx context.Context, identityID, teamID, cursor string, now time.Time) (AvailablePublicURLPage, error) {
	if !validStateText(identityID) || teamID != "" && !validStateText(teamID) || cursor != "" && !validStateText(cursor) {
		return AvailablePublicURLPage{}, ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return AvailablePublicURLPage{}, err
	}
	rows, err := controlstatedb.New(d.pool).ListVisitorAccessInventory(ctx, controlstatedb.ListVisitorAccessInventoryParams{
		IdentityID: identityID, TeamID: nullableText(teamID), Cursor: nullableText(cursor), Now: timestamptz(now),
	})
	if err != nil {
		return AvailablePublicURLPage{}, fmt.Errorf("controlstate: list available public URLs: %w", err)
	}
	page := AvailablePublicURLPage{PublicURLs: make([]AvailablePublicURL, min(len(rows), publicURLPageSize))}
	for index, row := range rows[:len(page.PublicURLs)] {
		item := AvailablePublicURL{
			ID: row.ID, TeamID: row.TeamID, TeamName: row.TeamName, CanonicalHostname: row.CanonicalHostname,
			ServiceProtocol: PublicURLServiceProtocol(row.ServiceProtocol), PublicURLScope: PublicURLScope(row.PublicURLScope),
			Purpose: PublicURLPurpose(row.Purpose), LifecycleState: PublicURLLifecycleState(row.LifecycleState),
			VisitorAccess: row.VisitorAccess,
		}
		if row.PublicPort.Valid {
			port := uint16(row.PublicPort.Int32)
			item.PublicPort = &port
		}
		page.PublicURLs[index] = item
	}
	if len(rows) > publicURLPageSize {
		page.NextCursor = rows[publicURLPageSize-1].ID
	}
	return page, nil
}
