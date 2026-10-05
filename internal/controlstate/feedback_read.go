package controlstate

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

func (d *Database) GetFeedback(ctx context.Context, id string) (FeedbackThread, error) {
	if !opaqueid.Valid(id, opaqueid.FeedbackPrefix) {
		return FeedbackThread{}, ErrFeedbackNotFound
	}
	if err := d.requireOpen(); err != nil {
		return FeedbackThread{}, err
	}
	row, err := controlstatedb.New(d.pool).GetFeedbackThread(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return FeedbackThread{}, ErrFeedbackNotFound
	}
	if err != nil {
		return FeedbackThread{}, fmt.Errorf("controlstate: read feedback thread: %w", err)
	}
	return feedbackThreadFromRow(row), nil
}

func (d *Database) ListFeedbackForPage(ctx context.Context, previewID, publicURLID, pagePath, cursor string) (FeedbackThreadPage, error) {
	if !opaqueid.Valid(previewID, opaqueid.PreviewPrefix) || publicURLID == "" || !validFeedbackPath(pagePath) ||
		cursor != "" && !opaqueid.Valid(cursor, opaqueid.FeedbackPrefix) {
		return FeedbackThreadPage{}, ErrFeedbackInvalid
	}
	if err := d.requireOpen(); err != nil {
		return FeedbackThreadPage{}, err
	}
	queries := controlstatedb.New(d.pool)
	highWater, err := queries.FeedbackEventHighWater(ctx)
	if err != nil {
		return FeedbackThreadPage{}, fmt.Errorf("controlstate: read feedback cursor: %w", err)
	}
	rows, err := queries.ListFeedbackThreadsForPage(ctx, controlstatedb.ListFeedbackThreadsForPageParams{
		PreviewID: previewID, PublicURLID: publicURLID, PagePath: pagePath, AfterID: cursor,
	})
	if err != nil {
		return FeedbackThreadPage{}, fmt.Errorf("controlstate: list page feedback: %w", err)
	}
	return feedbackThreadPage(rows, uint64(highWater)), nil
}

func (d *Database) ListFeedbackForTeam(ctx context.Context, teamID, cursor string) (FeedbackThreadPage, error) {
	if teamID == "" || cursor != "" && !opaqueid.Valid(cursor, opaqueid.FeedbackPrefix) {
		return FeedbackThreadPage{}, ErrFeedbackInvalid
	}
	if err := d.requireOpen(); err != nil {
		return FeedbackThreadPage{}, err
	}
	queries := controlstatedb.New(d.pool)
	highWater, err := queries.FeedbackEventHighWater(ctx)
	if err != nil {
		return FeedbackThreadPage{}, fmt.Errorf("controlstate: read feedback cursor: %w", err)
	}
	rows, err := queries.ListFeedbackThreadsForTeam(ctx, controlstatedb.ListFeedbackThreadsForTeamParams{
		TeamID: teamID, AfterID: cursor,
	})
	if err != nil {
		return FeedbackThreadPage{}, fmt.Errorf("controlstate: list team feedback: %w", err)
	}
	return feedbackThreadPage(rows, uint64(highWater)), nil
}

func feedbackThreadPage(rows []controlstatedb.ControlFeedbackThread, highWater uint64) FeedbackThreadPage {
	page := FeedbackThreadPage{Threads: make([]FeedbackThread, 0, min(len(rows), 100)), EventCursor: highWater}
	for index, row := range rows {
		if index == 100 {
			page.NextCursor = rows[index-1].ID
			break
		}
		page.Threads = append(page.Threads, feedbackThreadFromRow(row))
	}
	return page
}

func (d *Database) ListFeedbackEventsForThread(ctx context.Context, id string, after uint64) (FeedbackEventPage, error) {
	if !opaqueid.Valid(id, opaqueid.FeedbackPrefix) || after > 1<<63-1 {
		return FeedbackEventPage{}, ErrFeedbackInvalid
	}
	if err := d.requireOpen(); err != nil {
		return FeedbackEventPage{}, err
	}
	queries := controlstatedb.New(d.pool)
	highWater, err := queries.FeedbackEventHighWater(ctx)
	if err != nil {
		return FeedbackEventPage{}, fmt.Errorf("controlstate: read feedback cursor: %w", err)
	}
	rows, err := queries.ListFeedbackEventsForThread(ctx, controlstatedb.ListFeedbackEventsForThreadParams{
		FeedbackID: id, AfterCursor: int64(after),
	})
	if err != nil {
		return FeedbackEventPage{}, fmt.Errorf("controlstate: list feedback thread events: %w", err)
	}
	return feedbackEventPage(rows, uint64(highWater)), nil
}

func (d *Database) ListFeedbackEventsForTeam(ctx context.Context, teamID string, after uint64) (FeedbackEventPage, error) {
	if teamID == "" || after > 1<<63-1 {
		return FeedbackEventPage{}, ErrFeedbackInvalid
	}
	if err := d.requireOpen(); err != nil {
		return FeedbackEventPage{}, err
	}
	queries := controlstatedb.New(d.pool)
	highWater, err := queries.FeedbackEventHighWater(ctx)
	if err != nil {
		return FeedbackEventPage{}, fmt.Errorf("controlstate: read feedback cursor: %w", err)
	}
	rows, err := queries.ListFeedbackEventsForTeam(ctx, controlstatedb.ListFeedbackEventsForTeamParams{
		TeamID: teamID, AfterCursor: int64(after),
	})
	if err != nil {
		return FeedbackEventPage{}, fmt.Errorf("controlstate: list team feedback events: %w", err)
	}
	return feedbackEventPage(rows, uint64(highWater)), nil
}

func feedbackEventPage(rows []controlstatedb.ControlFeedbackEvent, highWater uint64) FeedbackEventPage {
	page := FeedbackEventPage{Events: make([]FeedbackEvent, 0, min(len(rows), 25)), EventCursor: highWater}
	for index, row := range rows {
		if index == 25 {
			page.NextCursor = uint64(rows[index-1].Cursor)
			break
		}
		page.Events = append(page.Events, feedbackEventFromRow(row))
	}
	return page
}
