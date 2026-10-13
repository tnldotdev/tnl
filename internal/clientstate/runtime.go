package clientstate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
)

const runtimeJournalByteLimit = 8 << 20

// RuntimeJournal holds one project's local app snapshot and retained events.
type RuntimeJournal struct {
	Project  string
	Snapshot []byte
	Events   [][]byte
}

// ReadRuntimeJournal reads a snapshot and its events in one SQLite transaction.
func (d *Database) ReadRuntimeJournal(ctx context.Context, project string) (RuntimeJournal, bool, error) {
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return RuntimeJournal{}, false, err
	}
	defer tx.Rollback()
	queries := d.queries.WithTx(tx)
	snapshot, err := queries.RuntimeSnapshot(ctx, project)
	if errors.Is(err, sql.ErrNoRows) {
		return RuntimeJournal{}, false, nil
	}
	if err != nil {
		return RuntimeJournal{}, false, err
	}
	events, err := queries.RuntimeEvents(ctx, project)
	if err != nil {
		return RuntimeJournal{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return RuntimeJournal{}, false, err
	}
	journal := RuntimeJournal{Project: project, Snapshot: []byte(snapshot), Events: make([][]byte, 0, len(events))}
	for _, event := range events {
		journal.Events = append(journal.Events, []byte(event))
	}
	return journal, true, nil
}

// ListRuntimeJournals reads all project snapshots and their events consistently.
func (d *Database) ListRuntimeJournals(ctx context.Context) ([]RuntimeJournal, error) {
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	queries := d.queries.WithTx(tx)
	rows, err := queries.ListRuntimeSnapshots(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]RuntimeJournal, 0, len(rows))
	for _, row := range rows {
		events, err := queries.RuntimeEvents(ctx, row.ProjectRoot)
		if err != nil {
			return nil, err
		}
		journal := RuntimeJournal{Project: row.ProjectRoot, Snapshot: []byte(row.SnapshotJson), Events: make([][]byte, 0, len(events))}
		for _, event := range events {
			journal.Events = append(journal.Events, []byte(event))
		}
		result = append(result, journal)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// SaveRuntimeJournal atomically advances the snapshot and appends one event.
// the retained history is bounded by both event count and serialized size.
func (d *Database) SaveRuntimeJournal(ctx context.Context, project string, cursor int64, snapshot, event []byte) error {
	if project == "" || cursor <= 0 || len(snapshot) > runtimeJournalByteLimit || len(event) > runtimeJournalByteLimit {
		return errors.New("clientstate: local runtime journal exceeds limit or has an invalid cursor")
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	queries := d.queries.WithTx(tx)
	if err := queries.UpsertRuntimeSnapshot(ctx, clientstatedb.UpsertRuntimeSnapshotParams{
		ProjectRoot: project, Cursor: cursor, SnapshotJson: string(snapshot),
	}); err != nil {
		return fmt.Errorf("clientstate: save runtime snapshot: %w", err)
	}
	if err := queries.InsertRuntimeEvent(ctx, clientstatedb.InsertRuntimeEventParams{
		ProjectRoot: project, Cursor: cursor, EventJson: string(event),
	}); err != nil {
		return fmt.Errorf("clientstate: append runtime event: %w", err)
	}
	sizes, err := queries.RuntimeEventSizes(ctx, project)
	if err != nil {
		return fmt.Errorf("clientstate: bound runtime events: %w", err)
	}
	var bytes int64
	oldest := cursor
	for _, entry := range sizes {
		if !entry.Size.Valid || bytes+entry.Size.Int64 > runtimeJournalByteLimit {
			break
		}
		bytes += entry.Size.Int64
		oldest = entry.Cursor
	}
	if err := queries.PruneRuntimeEvents(ctx, clientstatedb.PruneRuntimeEventsParams{ProjectRoot: project, OldestCursor: oldest}); err != nil {
		return fmt.Errorf("clientstate: prune runtime events: %w", err)
	}
	return tx.Commit()
}
