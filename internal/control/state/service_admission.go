package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

func lockEnabledService(ctx context.Context, tx pgx.Tx, id string) error {
	var found string
	err := tx.QueryRow(ctx, `SELECT id FROM control.services WHERE id = $1 AND enabled AND deleted_at IS NULL FOR UPDATE`, id).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrServiceAccess
	}
	return err
}

func minTime(first, second time.Time) time.Time {
	if first.Before(second) {
		return first
	}
	return second
}

// take the team lock before the saved service lock, matching grant and
// membership mutations; preparation cannot commit against a revoked grant.
func lockServiceAdmission(ctx context.Context, tx pgx.Tx, id string) error {
	var teamID string
	err := tx.QueryRow(ctx, `SELECT team_id FROM control.services WHERE id=$1`, id).Scan(&teamID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrServiceAccess
	}
	if err != nil {
		return err
	}
	var locked string
	err = tx.QueryRow(ctx, `SELECT id FROM control.teams WHERE id=$1 AND deleted_at IS NULL FOR SHARE`, teamID).Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrServiceAccess
	}
	if err != nil {
		return err
	}
	return lockEnabledService(ctx, tx, id)
}
