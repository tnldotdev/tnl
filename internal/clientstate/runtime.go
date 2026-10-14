package clientstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
)

const runtimeJournalByteLimit = 8 << 20

type RuntimeJournal struct {
	Project  string
	Cursor   int64
	Snapshot []byte
	Events   [][]byte
}

func (d *Database) ReadRuntimeJournal(ctx context.Context, project string) (RuntimeJournal, bool, error) {
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return RuntimeJournal{}, false, err
	}
	defer tx.Rollback()
	queries := d.queries.WithTx(tx)
	row, err := queries.RuntimeSnapshot(ctx, project)
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
	result := RuntimeJournal{Project: project, Cursor: row.Cursor, Snapshot: []byte(row.SnapshotJson)}
	for _, event := range events {
		result.Events = append(result.Events, []byte(event))
	}
	return result, true, nil
}

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
		journal := RuntimeJournal{Project: row.ProjectRoot, Cursor: row.Cursor, Snapshot: []byte(row.SnapshotJson)}
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

// SaveRuntimeJournal commits a manager snapshot and event under the next project
// cursor, including changes made by direct publishers in other processes.
func (d *Database) SaveRuntimeJournal(ctx context.Context, project string, snapshot, event []byte) (int64, error) {
	if project == "" || len(snapshot) > runtimeJournalByteLimit || len(event) > runtimeJournalByteLimit || !json.Valid(snapshot) || !json.Valid(event) {
		return 0, errors.New("clientstate: invalid or oversized project journal entry")
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	queries := d.queries.WithTx(tx)
	cursor, err := queries.UpsertRuntimeSnapshot(ctx, clientstatedb.UpsertRuntimeSnapshotParams{ProjectRoot: project, SnapshotJson: string(snapshot)})
	if err != nil {
		return 0, fmt.Errorf("clientstate: save runtime snapshot: %w", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(event, &fields); err != nil || fields == nil {
		return 0, errors.New("clientstate: invalid runtime event")
	}
	encoded, _ := json.Marshal(strconv.FormatInt(cursor, 10))
	fields["cursor"] = encoded
	if nested, ok := fields["snapshot"]; ok {
		var value map[string]json.RawMessage
		if err := json.Unmarshal(nested, &value); err != nil || value == nil {
			return 0, errors.New("clientstate: invalid runtime event snapshot")
		}
		value["cursor"] = encoded
		fields["snapshot"], err = json.Marshal(value)
		if err != nil {
			return 0, err
		}
	}
	event, err = json.Marshal(fields)
	if err != nil || len(event) > runtimeJournalByteLimit {
		return 0, errors.Join(err, errors.New("clientstate: event exceeds limit"))
	}
	if err := queries.InsertRuntimeEvent(ctx, clientstatedb.InsertRuntimeEventParams{ProjectRoot: project, Cursor: cursor, EventJson: string(event)}); err != nil {
		return 0, fmt.Errorf("clientstate: append runtime event: %w", err)
	}
	return cursor, tx.Commit()
}
