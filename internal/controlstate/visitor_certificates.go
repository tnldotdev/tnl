package controlstate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

// DatabaseVisitorAllowed checks current access for certificate issuance and
// each new database visitor connection. certificates never replace this check.
func (d *Database) DatabaseVisitorAllowed(ctx context.Context, publicURLID, identityID string, now time.Time) (bool, error) {
	if !opaqueid.Valid(publicURLID, opaqueid.PublicURLPrefix) || !validStateText(identityID) {
		return false, nil
	}
	if err := d.requireOpen(); err != nil {
		return false, err
	}
	allowed, err := controlstatedb.New(d.pool).DatabaseVisitorAllowed(ctx, controlstatedb.DatabaseVisitorAllowedParams{
		PublicURLID: publicURLID, IdentityID: identityID, Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check database visitor access: %w", err)
	}
	return allowed.Valid && allowed.Bool, nil
}
