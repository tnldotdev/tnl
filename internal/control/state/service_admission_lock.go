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

// cleanup joins the same authority queue as admission, but leaves busy owners
// for a later pass. no child lock is acquired before this parent decision.
func tryLockServiceOwner(ctx context.Context, tx pgx.Tx, id string) (bool, error) {
	var teamID, guestID pgtype.Text
	err := tx.QueryRow(ctx, `SELECT team_id,guest_id FROM control.services WHERE id=$1`, id).Scan(&teamID, &guestID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var locked string
	if guestID.Valid && !teamID.Valid {
		err = tx.QueryRow(ctx, `SELECT id FROM control.guest_trials WHERE id=$1 FOR UPDATE SKIP LOCKED`, guestID.String).Scan(&locked)
	} else if teamID.Valid && !guestID.Valid {
		var queued bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock_shared(hashtextextended('tnl:local-team:' || $1::text,0))`, teamID.String).Scan(&queued); err != nil {
			return false, err
		}
		if !queued {
			return false, nil
		}
		err = tx.QueryRow(ctx, `SELECT id FROM control.teams WHERE id=$1 AND deleted_at IS NULL FOR SHARE SKIP LOCKED`, teamID.String).Scan(&locked)
	} else {
		// neither a missing owner nor two owners can authorize cleanup.
		return false, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func lockServiceAdmission(ctx context.Context, tx pgx.Tx, id string) error {
	if err := lockServiceOwner(ctx, tx, id); err != nil {
		return err
	}
	return lockEnabledService(ctx, tx, id)
}

// a row lock alone lets a later reader join current readers while a writer
// waits. queue publication work after the owner and before any service or run
// row. the row locks still protect against writers outside publication.
func queueRunReader(ctx context.Context, tx pgx.Tx, id string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended('tnl:service-publication:' || $1::text,0))`, id)
	return err
}

func queueRunWriter(ctx context.Context, tx pgx.Tx, id string) error {
	if err := lockServiceOwner(ctx, tx, id); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('tnl:service-publication:' || $1::text,0))`, id)
	return err
}

func lockServiceForPublication(ctx context.Context, tx pgx.Tx, id string) error {
	if err := queueRunWriter(ctx, tx, id); err != nil {
		return err
	}
	return lockEnabledService(ctx, tx, id)
}

// run operations share the service row but still queue behind service edits and
// capacity writers. the caller locks the particular run before changing it.
func lockServiceForRun(ctx context.Context, tx pgx.Tx, id string) error {
	if err := lockServiceOwner(ctx, tx, id); err != nil {
		return err
	}
	if err := queueRunReader(ctx, tx, id); err != nil {
		return err
	}
	var found string
	err := tx.QueryRow(ctx, `SELECT id FROM control.services WHERE id=$1 AND enabled AND deleted_at IS NULL FOR SHARE`, id).Scan(&found)
	return publisherLookupError(err, ErrServiceAccess)
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
	if err := queueRunReader(ctx, tx, id); err != nil {
		return err
	}
	var found string
	err := tx.QueryRow(ctx, `SELECT id FROM control.services WHERE id = $1 AND enabled AND deleted_at IS NULL FOR KEY SHARE`, id).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrServiceAccess
	}
	return err
}
