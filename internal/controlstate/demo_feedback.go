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

func (d *Database) CreatePublishRunPreview(ctx context.Context, auth PublishRunAuthentication, now time.Time) (result Preview, retErr error) {
	if err := validatePublishRunAuthentication(auth); err != nil {
		return Preview{}, err
	}
	if err := d.requireOpen(); err != nil {
		return Preview{}, err
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return Preview{}, err
	}
	defer rollback(ctx, tx, "create demo preview", &retErr)()
	queries := controlstatedb.New(tx)
	run, err := queries.LockPublishRun(ctx, auth.PublishRunID)
	if err != nil || run.ClosedAt.Valid || run.PublicURLID != auth.PublicURLID || uint64(run.PublishRunNumber) != auth.PublishRunNumber {
		return Preview{}, ErrFeedbackAccess
	}
	id, err := opaqueid.New(opaqueid.PreviewPrefix)
	if err != nil {
		return Preview{}, err
	}
	row, err := queries.CreatePublishRunPreview(ctx, controlstatedb.CreatePublishRunPreviewParams{
		ID: id, PublishRunID: auth.PublishRunID, PublishRunNumber: int64(auth.PublishRunNumber), Now: timestamptz(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Preview{}, ErrFeedbackAccess
	}
	if err != nil {
		return Preview{}, fmt.Errorf("controlstate: create demo preview: %w", err)
	}
	if err := queries.AddPublishRunPreviewURL(ctx, controlstatedb.AddPublishRunPreviewURLParams{PreviewID: row.ID, Now: timestamptz(now)}); err != nil {
		return Preview{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Preview{}, err
	}
	return d.GetPreview(ctx, row.ID)
}
