package state

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

func (d *Database) ListPublicURLs(ctx context.Context, identityID, teamID, cursor string) (PublicURLPage, error) {
	if !validStateText(identityID) || !validStateText(teamID) || cursor != "" && !validStateText(cursor) {
		return PublicURLPage{}, ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return PublicURLPage{}, err
	}
	rows, err := controlstatedb.New(d.pool).ListIdentityPublicURLs(ctx, controlstatedb.ListIdentityPublicURLsParams{
		TeamID: teamID, Cursor: nullableText(cursor), IdentityID: identityID,
	})
	if err != nil {
		return PublicURLPage{}, fmt.Errorf("controlstate: list public_urls: %w", err)
	}
	if len(rows) == 0 {
		if _, err := d.GetTeam(ctx, identityID, teamID); err != nil {
			return PublicURLPage{}, err
		}
	}
	page := PublicURLPage{PublicURLs: make([]PublicURL, min(len(rows), publicURLPageSize))}
	for index := range page.PublicURLs {
		page.PublicURLs[index] = publicURLFromListRow(rows[index])
		if err := d.restorePublicURLPolicy(&page.PublicURLs[index], rows[index].AllowedIpPolicyStorageKeyID,
			rows[index].AllowedIpPolicyCiphertext, rows[index].AllowedIpHashes); err != nil {
			return PublicURLPage{}, err
		}
	}
	if len(rows) > publicURLPageSize {
		page.NextCursor = rows[publicURLPageSize-1].ID
	}
	return page, nil
}

// ListAuthorizedPublicURLs returns one team page after the caller has obtained a
// current authorization decision. it does not consult local memberships.
func (d *Database) ListAuthorizedPublicURLs(ctx context.Context, teamID, cursor string) (PublicURLPage, error) {
	if !validStateText(teamID) || cursor != "" && !validStateText(cursor) {
		return PublicURLPage{}, ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return PublicURLPage{}, err
	}
	rows, err := controlstatedb.New(d.pool).ListAuthorizedPublicURLsData(
		ctx,
		controlstatedb.ListAuthorizedPublicURLsDataParams{TeamID: teamID, Cursor: nullableText(cursor)},
	)
	if err != nil {
		return PublicURLPage{}, fmt.Errorf("controlstate: list authorized public_urls: %w", err)
	}
	page := PublicURLPage{PublicURLs: make([]PublicURL, min(len(rows), publicURLPageSize))}
	for index := range page.PublicURLs {
		page.PublicURLs[index] = publicURLFromAuthorizedListRow(rows[index])
		if err := d.restorePublicURLPolicy(&page.PublicURLs[index], rows[index].AllowedIpPolicyStorageKeyID,
			rows[index].AllowedIpPolicyCiphertext, rows[index].AllowedIpHashes); err != nil {
			return PublicURLPage{}, err
		}
	}
	if len(rows) > publicURLPageSize {
		page.NextCursor = rows[publicURLPageSize-1].ID
	}
	return page, nil
}

// GetAuthorizedPublicURLByHostname reads one non-deleted public URL after a current
// team-read authorization decision, using the existing hostname index.
func (d *Database) GetAuthorizedPublicURLByHostname(ctx context.Context, teamID, hostname string) (PublicURL, error) {
	canonical, err := naming.CanonicalizeHostname(hostname)
	if !validStateText(teamID) || err != nil || canonical != hostname {
		return PublicURL{}, ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return PublicURL{}, err
	}
	row, err := controlstatedb.New(d.pool).GetAuthorizedPublicURLByHostname(ctx, controlstatedb.GetAuthorizedPublicURLByHostnameParams{
		TeamID: teamID, CanonicalHostname: hostname,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PublicURL{}, ErrPublicURLNotFound
	}
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: get authorized route by hostname: %w", err)
	}
	result := publicURLFromAuthorizedListRow(controlstatedb.ListAuthorizedPublicURLsDataRow(row))
	if err := d.restorePublicURLPolicy(&result, row.AllowedIpPolicyStorageKeyID, row.AllowedIpPolicyCiphertext, row.AllowedIpHashes); err != nil {
		return PublicURL{}, err
	}
	return result, nil
}

func (d *Database) GetPublicURL(ctx context.Context, identityID, publicURLID string) (PublicURL, error) {
	if !validStateText(identityID) || !validStateText(publicURLID) {
		return PublicURL{}, ErrPublicURLInvalid
	}
	if err := d.requireOpen(); err != nil {
		return PublicURL{}, err
	}
	row, err := controlstatedb.New(d.pool).GetIdentityPublicURL(ctx, controlstatedb.GetIdentityPublicURLParams{
		PublicURLID: publicURLID, IdentityID: identityID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return PublicURL{}, ErrPublicURLNotFound
	}
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: get public_url: %w", err)
	}
	result := publicURLFromIdentityRow(row)
	if err := d.restorePublicURLPolicy(&result, row.AllowedIpPolicyStorageKeyID, row.AllowedIpPolicyCiphertext, row.AllowedIpHashes); err != nil {
		return PublicURL{}, err
	}
	return result, nil
}
