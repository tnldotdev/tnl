package state

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func lockEnabledService(ctx context.Context, tx pgx.Tx, id string) error {
	var found string
	err := tx.QueryRow(ctx, `SELECT id FROM control.services WHERE id = $1 AND enabled AND deleted_at IS NULL FOR UPDATE`, id).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrServiceAccess
	}
	return err
}

// ownership is immutable. resolve it without a child lock, then acquire the
// team or trial before the saved service and any run, publisher, or grant.
// expiration and deletion use this same order without requiring a live service.
func lockServiceOwner(ctx context.Context, tx pgx.Tx, id string) error {
	var teamID, guestID pgtype.Text
	err := tx.QueryRow(ctx, `SELECT team_id,guest_id FROM control.services WHERE id=$1`, id).Scan(&teamID, &guestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrServiceAccess
	}
	if err != nil {
		return err
	}
	var locked string
	if guestID.Valid && !teamID.Valid {
		err = tx.QueryRow(ctx, `SELECT id FROM control.guest_trials WHERE id=$1 FOR UPDATE`, guestID.String).Scan(&locked)
	} else if teamID.Valid && !guestID.Valid {
		err = tx.QueryRow(ctx, `SELECT id FROM control.teams WHERE id=$1 AND deleted_at IS NULL FOR SHARE`, teamID.String).Scan(&locked)
	} else {
		return ErrServiceAccess
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrServiceAccess
	}
	if err != nil {
		return err
	}
	return nil
}

func lockServiceAdmission(ctx context.Context, tx pgx.Tx, id string) error {
	if err := lockServiceOwner(ctx, tx, id); err != nil {
		return err
	}
	return lockEnabledService(ctx, tx, id)
}
