package clientstate

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate/clientstatedb"
	"github.com/tnldotdev/tnl/internal/failure"
)

const RuntimeEventRetention = 2048
const RuntimeEventBytes = 8 << 20

var ErrRuntimeCursorExpired = errors.New("local event cursor expired; read a new status snapshot")
var ErrRuntimeConflict = errors.New("clientstate: runtime snapshot changed; read a new snapshot before updating")

// RuntimeSnapshot is one transactional project view. service values belong to
// the app runtime; publication observations are maintained by native tunnels.
// callers treat cursors as opaque and use RuntimeEventsAfter for exclusive resume.
type RuntimeSnapshot struct {
	SchemaVersion int               `json:"schema_version"`
	Project       string            `json:"project"`
	Cursor        string            `json:"cursor"`
	ObservedAt    time.Time         `json:"observed_at"`
	Services      []json.RawMessage `json:"services"`
	Publications  []TunnelInfo      `json:"publications,omitempty"`
	Events        []RuntimeEvent    `json:"-"`
}

type RuntimeEvent struct {
	Cursor  string
	Type    string
	At      time.Time
	Payload json.RawMessage
}

type RuntimeUpdate struct {
	// nil services append an event without replacing the app snapshot. non-nil
	// services require ExpectedCursor to prevent lost updates from app writers.
	Services       []json.RawMessage
	ExpectedCursor string
	Type           string
	Payload        json.RawMessage
	// snapshot embeds the exact committed project view in the event payload.
	Snapshot bool
}

func runtimeProject(project string) (string, error) {
	if !filepath.IsAbs(project) || filepath.Clean(project) != project || len(project) > 4096 {
		return "", errors.New("clientstate: canonical absolute runtime project path is required")
	}
	return project, nil
}

func runtimeCursor(epoch string, sequence int64) string {
	return fmt.Sprintf("ev_%s_%016x", epoch, sequence)
}

func cursorSequence(cursor, epoch string) (int64, error) {
	prefix := "ev_" + epoch + "_"
	if !strings.HasPrefix(cursor, prefix) || len(cursor) != len(prefix)+16 {
		return 0, expiredRuntimeCursor()
	}
	sequence, err := strconv.ParseInt(cursor[len(prefix):], 16, 64)
	if err != nil || runtimeCursor(epoch, sequence) != cursor {
		return 0, expiredRuntimeCursor()
	}
	return sequence, nil
}

func expiredRuntimeCursor() error {
	return failure.Wrap("resume local events", failure.AppCursorExpired, ErrRuntimeCursorExpired)
}

// ReadRuntimeSnapshot reads services, publications, cursor, and retained events
// in one transaction. an empty project is initialized under SQLite's writer lock.
func (d *Database) ReadRuntimeSnapshot(ctx context.Context, project string) (RuntimeSnapshot, error) {
	project, err := runtimeProject(project)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	if err := d.queries.EnsureRuntimeProject(ctx, project); err != nil {
		return RuntimeSnapshot{}, err
	}
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	defer tx.Rollback()
	snapshot, err := d.readRuntimeSnapshot(ctx, d.queries.WithTx(tx), project)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	return snapshot, tx.Commit()
}

func (d *Database) ListRuntimeSnapshots(ctx context.Context) ([]RuntimeSnapshot, error) {
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	queries := d.queries.WithTx(tx)
	projects, err := queries.ListRuntimeProjects(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]RuntimeSnapshot, 0, len(projects))
	for _, project := range projects {
		snapshot, err := d.readRuntimeSnapshot(ctx, queries, project)
		if err != nil {
			return nil, err
		}
		result = append(result, snapshot)
	}
	return result, tx.Commit()
}

// KnownProjectURLs is a bounded, read-only set of public URL IDs previously
// observed for this project and server. callers must still check the grant and
// hostname before choosing a publication.
func (d *Database) KnownProjectURLs(ctx context.Context, project, server string) ([]string, error) {
	if _, err := runtimeProject(project); err != nil {
		return nil, err
	}
	origin, err := CanonicalServer(server)
	if err != nil {
		return nil, err
	}
	return d.queries.ListKnownProjectURLs(ctx, clientstatedb.ListKnownProjectURLsParams{ProjectRoot: project, ServerOrigin: origin})
}

// CommitRuntimeUpdate allocates the cursor in SQLite and commits the snapshot,
// event, and retention together. it never trusts a writer's event history.
func (d *Database) CommitRuntimeUpdate(ctx context.Context, project string, update RuntimeUpdate) (RuntimeSnapshot, error) {
	project, err := runtimeProject(project)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	if !validOpaqueValue(update.Type, 128) || !jsonObject(update.Payload) || len(update.Payload)+len(update.Type)+128 > RuntimeEventBytes {
		return RuntimeSnapshot{}, errors.New("clientstate: invalid runtime event")
	}
	var services []byte
	if update.Services != nil {
		if update.ExpectedCursor == "" {
			return RuntimeSnapshot{}, ErrRuntimeConflict
		}
		for _, service := range update.Services {
			if !jsonObject(service) {
				return RuntimeSnapshot{}, errors.New("clientstate: invalid runtime service")
			}
		}
		services, err = json.Marshal(update.Services)
		if err != nil || len(services) > RuntimeEventBytes {
			return RuntimeSnapshot{}, errors.New("clientstate: invalid runtime services")
		}
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	defer tx.Rollback()
	queries := d.queries.WithTx(tx)
	// write first, before reading the row, so competing writers cannot upgrade a
	// stale read transaction or allocate the same sequence.
	if err := queries.EnsureRuntimeProject(ctx, project); err != nil {
		return RuntimeSnapshot{}, err
	}
	row, err := queries.GetRuntimeProject(ctx, project)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	if update.ExpectedCursor != "" {
		after, err := cursorSequence(update.ExpectedCursor, row.CursorEpoch)
		if err != nil || after > row.LastSequence || after < row.LastAppSequence {
			return RuntimeSnapshot{}, ErrRuntimeConflict
		}
	}
	row, err = queries.AdvanceRuntimeProject(ctx, clientstatedb.AdvanceRuntimeProjectParams{ProjectRoot: project,
		Now: sql.NullInt64{Int64: d.now().UTC().UnixNano(), Valid: true}})
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	if services != nil {
		if err := queries.SetRuntimeServices(ctx, clientstatedb.SetRuntimeServicesParams{ProjectRoot: project, ServicesJson: string(services)}); err != nil {
			return RuntimeSnapshot{}, err
		}
	}
	payload := update.Payload
	if update.Snapshot {
		view, err := d.runtimeView(ctx, queries, project, false)
		if err != nil {
			return RuntimeSnapshot{}, err
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(payload, &fields); err != nil {
			return RuntimeSnapshot{}, err
		}
		fields["snapshot"], err = json.Marshal(view)
		if err != nil {
			return RuntimeSnapshot{}, err
		}
		payload, err = json.Marshal(fields)
		if err != nil || len(payload)+len(update.Type)+128 > RuntimeEventBytes {
			return RuntimeSnapshot{}, errors.New("clientstate: runtime snapshot event exceeds limit")
		}
	}
	if err := queries.InsertRuntimeEvent(ctx, clientstatedb.InsertRuntimeEventParams{ProjectRoot: project, Sequence: row.LastSequence, EventType: update.Type, CreatedAt: row.LastObservedAt.Int64, Payload: string(payload)}); err != nil {
		return RuntimeSnapshot{}, err
	}
	snapshot, err := d.readRuntimeSnapshot(ctx, queries, project)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	return snapshot, tx.Commit()
}

func jsonObject(value []byte) bool {
	value = bytes.TrimSpace(value)
	return len(value) > 0 && value[0] == '{' && json.Valid(value)
}

func (d *Database) readRuntimeSnapshot(ctx context.Context, queries *clientstatedb.Queries, project string) (RuntimeSnapshot, error) {
	return d.runtimeView(ctx, queries, project, true)
}

func (d *Database) runtimeView(ctx context.Context, queries *clientstatedb.Queries, project string, includeEvents bool) (RuntimeSnapshot, error) {
	row, err := queries.GetRuntimeProject(ctx, project)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	result := RuntimeSnapshot{SchemaVersion: 1, Project: project, Cursor: runtimeCursor(row.CursorEpoch, row.LastSequence), ObservedAt: unixNanoTime(row.LastObservedAt.Int64), Publications: []TunnelInfo{}}
	if err := json.Unmarshal([]byte(row.AppServicesJson), &result.Services); err != nil {
		return RuntimeSnapshot{}, err
	}
	publications, err := queries.ListOpenTunnelsForProject(ctx, project)
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	observedAt := d.now().UTC()
	for _, publication := range publications {
		result.Publications = append(result.Publications, tunnelInfo(publication, observedAt))
	}
	if !includeEvents {
		return result, nil
	}
	events, err := queries.ListRuntimeEvents(ctx, clientstatedb.ListRuntimeEventsParams{ProjectRoot: project, After: 0})
	if err != nil {
		return RuntimeSnapshot{}, err
	}
	result.Events = make([]RuntimeEvent, 0, len(events))
	for _, event := range events {
		result.Events = append(result.Events, RuntimeEvent{Cursor: runtimeCursor(row.CursorEpoch, event.Sequence), Type: event.EventType, At: unixNanoTime(event.OccurredAt), Payload: json.RawMessage(event.PayloadJson)})
	}
	return result, nil
}

func (d *Database) RuntimeEventsAfter(ctx context.Context, project, cursor string) ([]RuntimeEvent, error) {
	project, err := runtimeProject(project)
	if err != nil {
		return nil, err
	}
	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	queries := d.queries.WithTx(tx)
	row, err := queries.GetRuntimeProject(ctx, project)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, expiredRuntimeCursor()
	}
	if err != nil {
		return nil, err
	}
	after, err := cursorSequence(cursor, row.CursorEpoch)
	if err != nil || after > row.LastSequence {
		return nil, expiredRuntimeCursor()
	}
	oldest, err := queries.OldestRuntimeEvent(ctx, project)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil && after < oldest-1 || errors.Is(err, sql.ErrNoRows) && after != row.LastSequence {
		return nil, expiredRuntimeCursor()
	}
	rows, err := queries.ListRuntimeEvents(ctx, clientstatedb.ListRuntimeEventsParams{ProjectRoot: project, After: after})
	if err != nil {
		return nil, err
	}
	result := make([]RuntimeEvent, 0, len(rows))
	for _, event := range rows {
		result = append(result, RuntimeEvent{Cursor: runtimeCursor(row.CursorEpoch, event.Sequence), Type: event.EventType, At: unixNanoTime(event.OccurredAt), Payload: json.RawMessage(event.PayloadJson)})
	}
	return result, tx.Commit()
}

// RuntimeEventsAfter resumes from the exact snapshot's retained interval.
func RuntimeEventsAfter(snapshot RuntimeSnapshot, cursor string) ([]RuntimeEvent, error) {
	if len(snapshot.Cursor) != 52 {
		return nil, expiredRuntimeCursor()
	}
	epoch := snapshot.Cursor[3:35]
	latest, err := cursorSequence(snapshot.Cursor, epoch)
	if err != nil {
		return nil, err
	}
	after, err := cursorSequence(cursor, epoch)
	if err != nil || after > latest {
		return nil, expiredRuntimeCursor()
	}
	if len(snapshot.Events) == 0 {
		if after != latest {
			return nil, expiredRuntimeCursor()
		}
		return []RuntimeEvent{}, nil
	}
	first, err := cursorSequence(snapshot.Events[0].Cursor, epoch)
	if err != nil || after < first-1 {
		return nil, expiredRuntimeCursor()
	}
	result := []RuntimeEvent{}
	for _, event := range snapshot.Events {
		sequence, err := cursorSequence(event.Cursor, epoch)
		if err != nil {
			return nil, err
		}
		if sequence > after {
			result = append(result, event)
		}
	}
	return result, nil
}
