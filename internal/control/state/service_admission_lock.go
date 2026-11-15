package state

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
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
		// queue with authority writers before taking the team row, so repeated
		// service admissions cannot keep bypassing a waiting mutation.
		locked, err = controlstatedb.New(tx).LockLocalTeamForSession(ctx, teamID.String)
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

// visitor capacity writers serialize reservations and deadline extensions without
// excluding policy observations. authority and lifecycle writers retain FOR UPDATE.
func lockPublicServiceVisitorCapacity(ctx context.Context, tx pgx.Tx, id string) error {
	if err := lockServiceOwner(ctx, tx, id); err != nil {
		return err
	}
	var found string
	err := tx.QueryRow(ctx, `SELECT id FROM control.services WHERE id = $1 AND enabled AND deleted_at IS NULL FOR NO KEY UPDATE`, id).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrServiceAccess
	}
	return err
}

// policy observations do not reserve capacity or extend visitor deadlines.
// explicit authority writers still exclude them with the service's FOR UPDATE.
func lockPublisherVisitorPolicy(ctx context.Context, tx pgx.Tx, id string) error {
	if err := lockServiceOwner(ctx, tx, id); err != nil {
		return err
	}
	var found string
	err := tx.QueryRow(ctx, `SELECT id FROM control.services WHERE id = $1 AND enabled AND deleted_at IS NULL FOR KEY SHARE`, id).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrServiceAccess
	}
	return err
}
