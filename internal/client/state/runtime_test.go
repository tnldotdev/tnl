package clientstate

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/state/clientstatedb"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestRuntimeJournalUnifiesAppNamedAndDirectPublications(t *testing.T) {
	database := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	project := t.TempDir()
	initial, err := database.ReadRuntimeSnapshot(t.Context(), project)
	if err != nil {
		t.Fatal(err)
	}
	app, err := database.CommitRuntimeUpdate(t.Context(), project, RuntimeUpdate{ExpectedCursor: initial.Cursor,
		Services: []json.RawMessage{json.RawMessage(`{"service":"web","registered":true}`)}, Type: "service.registered", Payload: json.RawMessage(`{"service":{"service":"web"}}`)})
	if err != nil {
		t.Fatal(err)
	}
	for _, options := range []BeginTunnelOptions{
		{Command: TunnelCommandPublish, Server: "https://server.example", Target: "5432", Project: project, Service: "database"},
		{Command: TunnelCommandPublish, Server: "https://server.example", Target: "3000", Project: project},
	} {
		tunnel, err := database.BeginTunnel(t.Context(), options)
		if err != nil {
			t.Fatal(err)
		}
		if err := tunnel.SetPublicURL(t.Context(), testPublicURLID, "service.example"); err != nil {
			t.Fatal(err)
		}
		publicURL := "https://service.example"
		if err := tunnel.SetReady(t.Context(), publicURL, 1); err != nil {
			t.Fatal(err)
		}
		defer tunnel.Finish(context.Background(), nil)
	}
	// publication changes since the app snapshot do not conflict with its writer.
	next, err := database.CommitRuntimeUpdate(t.Context(), project, RuntimeUpdate{ExpectedCursor: app.Cursor,
		Services: []json.RawMessage{json.RawMessage(`{"service":"web","ready":true}`)}, Type: "service.readiness", Payload: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Publications) != 2 || len(next.Services) != 1 || len(next.Events) != 8 {
		t.Fatalf("unified snapshot: %#v", next)
	}
	if next.Events[len(next.Events)-1].Cursor != next.Cursor {
		t.Fatal("snapshot/event cursor mismatch")
	}
	events, err := database.RuntimeEventsAfter(t.Context(), project, app.Cursor)
	if err != nil || len(events) != 7 {
		t.Fatalf("exclusive resume: %d, %v", len(events), err)
	}
	for index := 1; index < len(next.Events); index++ {
		if next.Events[index].Cursor <= next.Events[index-1].Cursor {
			t.Fatal("cursor did not increase")
		}
	}
	if _, err := database.CommitRuntimeUpdate(t.Context(), project, RuntimeUpdate{ExpectedCursor: app.Cursor, Services: []json.RawMessage{}, Type: "stale.writer", Payload: json.RawMessage(`{}`)}); !errors.Is(err, ErrRuntimeConflict) {
		t.Fatalf("stale app writer: %v", err)
	}
}

func TestRuntimeUpdateRollsBackSnapshotCursorAndEvent(t *testing.T) {
	database := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	project := t.TempDir()
	initial, err := database.ReadRuntimeSnapshot(t.Context(), project)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.db.ExecContext(t.Context(), `CREATE TRIGGER reject_event BEFORE INSERT ON project_events WHEN NEW.event_type = 'reject' BEGIN SELECT RAISE(ABORT, 'rejected'); END;`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CommitRuntimeUpdate(t.Context(), project, RuntimeUpdate{ExpectedCursor: initial.Cursor, Services: []json.RawMessage{json.RawMessage(`{"service":"bad"}`)}, Type: "reject", Payload: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("rejected event committed")
	}
	got, err := database.ReadRuntimeSnapshot(t.Context(), project)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cursor != initial.Cursor || len(got.Services) != 0 || len(got.Events) != 0 {
		t.Fatalf("partial transaction: %#v", got)
	}
}

func TestRuntimeConcurrentConnectionsAndRestart(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	project := t.TempDir()
	first := openFileDatabase(t, root)
	initial, err := first.ReadRuntimeSnapshot(t.Context(), project)
	if err != nil {
		t.Fatal(err)
	}
	const writers, perWriter = 6, 24
	databases := make([]*Database, writers)
	for index := range databases {
		databases[index] = openFileDatabase(t, root)
	}
	var wait sync.WaitGroup
	errorsFound := make(chan error, writers)
	readerStop := make(chan struct{})
	readerDone := make(chan error, 1)
	go func() {
		for {
			select {
			case <-readerStop:
				readerDone <- nil
				return
			default:
			}
			snapshot, err := first.ReadRuntimeSnapshot(t.Context(), project)
			if err != nil {
				readerDone <- err
				return
			}
			if len(snapshot.Events) > 0 && snapshot.Events[len(snapshot.Events)-1].Cursor != snapshot.Cursor {
				readerDone <- errors.New("reader observed a cursor without its event")
				return
			}
		}
	}()
	for index, database := range databases {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for number := range perWriter {
				snapshot, err := database.CommitRuntimeUpdate(t.Context(), project, RuntimeUpdate{Type: "concurrent", Payload: json.RawMessage(fmt.Sprintf(`{"writer":%d,"number":%d}`, index, number))})
				if err != nil {
					errorsFound <- err
					return
				}
				if len(snapshot.Events) == 0 || snapshot.Events[len(snapshot.Events)-1].Cursor != snapshot.Cursor {
					errorsFound <- errors.New("inconsistent transaction")
					return
				}
			}
		}()
	}
	wait.Wait()
	close(readerStop)
	if err := <-readerDone; err != nil {
		t.Fatal(err)
	}
	close(errorsFound)
	for err := range errorsFound {
		t.Fatal(err)
	}
	snapshot, err := first.ReadRuntimeSnapshot(t.Context(), project)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Events) != writers*perWriter {
		t.Fatalf("lost events: %d", len(snapshot.Events))
	}
	for index := 1; index < len(snapshot.Events); index++ {
		if snapshot.Events[index].Cursor <= snapshot.Events[index-1].Cursor {
			t.Fatal("duplicate/reversed cursor")
		}
	}
	for _, database := range databases {
		database.Close()
	}
	first.Close()
	reopened := openFileDatabase(t, root)
	resumed, err := reopened.RuntimeEventsAfter(t.Context(), project, initial.Cursor)
	if err != nil || len(resumed) != writers*perWriter {
		t.Fatalf("restart history: %d, %v", len(resumed), err)
	}
	next, err := reopened.CommitRuntimeUpdate(t.Context(), project, RuntimeUpdate{Type: "restarted", Payload: json.RawMessage(`{}`)})
	if err != nil || next.Cursor <= snapshot.Cursor {
		t.Fatalf("restart cursor: %q <= %q, %v", next.Cursor, snapshot.Cursor, err)
	}
	other := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	if _, err := other.RuntimeEventsAfter(t.Context(), project, snapshot.Cursor); !errors.Is(err, ErrRuntimeCursorExpired) {
		t.Fatalf("foreign database cursor: %v", err)
	}
}

func TestRuntimeRetentionCountBytesAndAuthoredStaleCursor(t *testing.T) {
	for _, mode := range []string{"count", "bytes"} {
		t.Run(mode, func(t *testing.T) {
			database := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
			project := t.TempDir()
			initial, err := database.ReadRuntimeSnapshot(t.Context(), project)
			if err != nil {
				t.Fatal(err)
			}
			count, payload := RuntimeEventRetention+3, json.RawMessage(`{}`)
			if mode == "bytes" {
				count = 18
				payload = json.RawMessage(`{"value":"` + strings.Repeat("a", 600000) + `"}`)
			}
			// exercise retention at its SQL boundary without rereading the entire
			// growing history for every fixture row. the final write uses the API.
			tx, err := database.db.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			queries := database.queries.WithTx(tx)
			for range count - 1 {
				row, err := queries.AdvanceRuntimeProject(t.Context(), clientstatedb.AdvanceRuntimeProjectParams{ProjectRoot: project,
					Now: sql.NullInt64{Int64: database.now().UnixNano(), Valid: true}})
				if err != nil {
					t.Fatal(err)
				}
				if err := queries.InsertRuntimeEvent(t.Context(), clientstatedb.InsertRuntimeEventParams{ProjectRoot: project, Sequence: row.LastSequence, EventType: "retained", CreatedAt: row.LastObservedAt.Int64, Payload: string(payload)}); err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			latest, err := database.CommitRuntimeUpdate(t.Context(), project, RuntimeUpdate{Type: "retained", Payload: payload})
			if err != nil {
				t.Fatal(err)
			}
			var retained, used int64
			if err := database.db.QueryRowContext(t.Context(), "SELECT count(*), sum(stored_bytes) FROM project_events WHERE project_root = ?", project).Scan(&retained, &used); err != nil {
				t.Fatal(err)
			}
			if retained > RuntimeEventRetention || used > RuntimeEventBytes || retained >= int64(count) {
				t.Fatalf("unbounded retention: %d, %d", retained, used)
			}
			if mode == "count" && retained != RuntimeEventRetention {
				t.Fatalf("count retention: %d", retained)
			}
			for _, cursor := range []string{initial.Cursor, "0", "99999", latest.Cursor + "x"} {
				_, err := database.RuntimeEventsAfter(t.Context(), project, cursor)
				if !errors.Is(err, ErrRuntimeCursorExpired) {
					t.Fatalf("stale cursor accepted: %q, %v", cursor, err)
				}
				reason, _, ok := failure.Describe(err)
				if !ok || reason != failure.AppCursorExpired {
					t.Fatalf("stale cursor lacks authored failure: %v", err)
				}
			}
			empty, err := database.RuntimeEventsAfter(t.Context(), project, latest.Cursor)
			if err != nil || len(empty) != 0 {
				t.Fatalf("latest cursor replayed: %d, %v", len(empty), err)
			}
			row, err := database.queries.GetRuntimeProject(t.Context(), project)
			if err != nil {
				t.Fatal(err)
			}
			if row.EventCount != retained || row.EventBytes != used {
				t.Fatalf("retention accounting drift: count %d/%d, bytes %d/%d", row.EventCount, retained, row.EventBytes, used)
			}
			firstSequence, err := cursorSequence(latest.Events[0].Cursor, row.CursorEpoch)
			if err != nil {
				t.Fatal(err)
			}
			events, err := database.RuntimeEventsAfter(t.Context(), project, runtimeCursor(row.CursorEpoch, firstSequence-1))
			if err != nil || len(events) != len(latest.Events) {
				t.Fatalf("retention boundary resume: %d, %v", len(events), err)
			}
			if _, err := database.RuntimeEventsAfter(t.Context(), project, runtimeCursor(row.CursorEpoch, row.LastSequence+1)); !errors.Is(err, ErrRuntimeCursorExpired) {
				t.Fatalf("future cursor accepted: %v", err)
			}
		})
	}
}

func TestRuntimeRetentionAccountingFollowsTransactionAndProject(t *testing.T) {
	database := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	project, other := t.TempDir(), t.TempDir()
	for _, root := range []string{project, other} {
		if _, err := database.CommitRuntimeUpdate(t.Context(), root, RuntimeUpdate{Type: "retained", Payload: json.RawMessage(`{}`)}); err != nil {
			t.Fatal(err)
		}
	}
	before, err := database.queries.GetRuntimeProject(t.Context(), project)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := database.db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(t.Context(), "DELETE FROM project_events WHERE project_root = ?", project); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	after, err := database.queries.GetRuntimeProject(t.Context(), project)
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatal("rolled-back eviction changed the journal budget", err)
	}
	if _, err := database.db.ExecContext(t.Context(), "DELETE FROM project_journals WHERE project_root = ?", project); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CommitRuntimeUpdate(t.Context(), project, RuntimeUpdate{Type: "retained", Payload: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{project, other} {
		row, err := database.queries.GetRuntimeProject(t.Context(), root)
		if err != nil || row.EventCount != 1 || row.EventBytes != before.EventBytes {
			t.Fatal("project deletion changed another or recreated journal's budget", err)
		}
	}
}

func TestRuntimeConcurrentAppSnapshotWritersCollideWithoutLostState(t *testing.T) {
	root, project := filepath.Join(t.TempDir(), "state"), t.TempDir()
	database := openFileDatabase(t, root)
	initial, err := database.ReadRuntimeSnapshot(t.Context(), project)
	if err != nil {
		t.Fatal(err)
	}
	const writers = 6
	connections := make([]*Database, writers)
	for index := range connections {
		connections[index] = openFileDatabase(t, root)
	}
	type result struct {
		index    int
		snapshot RuntimeSnapshot
		err      error
	}
	start := make(chan struct{})
	results := make(chan result, writers)
	for index, connection := range connections {
		go func() {
			<-start
			service := json.RawMessage(fmt.Sprintf(`{"service":"writer-%d"}`, index))
			snapshot, err := connection.CommitRuntimeUpdate(t.Context(), project, RuntimeUpdate{
				ExpectedCursor: initial.Cursor, Services: []json.RawMessage{service},
				Type: "runtime.configured", Payload: json.RawMessage(`{}`), Snapshot: true,
			})
			results <- result{index: index, snapshot: snapshot, err: err}
		}()
	}
	close(start)
	winner, conflicts := -1, 0
	var committed RuntimeSnapshot
	for range writers {
		result := <-results
		if result.err == nil {
			if winner != -1 {
				t.Fatal("two app writers committed from the same cursor")
			}
			winner, committed = result.index, result.snapshot
		} else if errors.Is(result.err, ErrRuntimeConflict) {
			conflicts++
		} else {
			t.Fatalf("app writer failed outside the conflict boundary: %v", result.err)
		}
	}
	if winner < 0 || conflicts != writers-1 {
		t.Fatalf("winner = %d, conflicts = %d", winner, conflicts)
	}
	for _, connection := range connections {
		if err := connection.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := openFileDatabase(t, root)
	snapshot, err := reopened.ReadRuntimeSnapshot(t.Context(), project)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf(`{"service":"writer-%d"}`, winner)
	if snapshot.Cursor != committed.Cursor || len(snapshot.Services) != 1 || string(snapshot.Services[0]) != want || len(snapshot.Events) != 1 || snapshot.Events[0].Cursor != snapshot.Cursor {
		t.Fatalf("losing writer changed the committed state: %#v", snapshot)
	}
	var event struct {
		Snapshot RuntimeSnapshot `json:"snapshot"`
	}
	if err := json.Unmarshal(snapshot.Events[0].Payload, &event); err != nil {
		t.Fatal(err)
	}
	if event.Snapshot.Cursor != snapshot.Cursor || len(event.Snapshot.Services) != 1 || string(event.Snapshot.Services[0]) != want {
		t.Fatal("snapshot event did not preserve the winning app writer")
	}
}

func TestRuntimeCursorsCannotResumeAnotherProjectInSameDatabase(t *testing.T) {
	database := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	projects := []string{t.TempDir(), t.TempDir()}
	snapshots := make([]RuntimeSnapshot, len(projects))
	for index, project := range projects {
		snapshot, err := database.ReadRuntimeSnapshot(t.Context(), project)
		if err != nil {
			t.Fatal(err)
		}
		snapshots[index] = snapshot
	}
	for _, phase := range []string{"empty", "populated"} {
		t.Run(phase, func(t *testing.T) {
			if phase == "populated" {
				for index, project := range projects {
					snapshot, err := database.CommitRuntimeUpdate(t.Context(), project, RuntimeUpdate{Type: "project.event", Payload: json.RawMessage(`{}`)})
					if err != nil {
						t.Fatal(err)
					}
					snapshots[index] = snapshot
				}
			}
			for index, snapshot := range snapshots {
				foreign := snapshots[1-index].Cursor
				if snapshot.Cursor == foreign {
					t.Fatal("projects shared a cursor epoch")
				}
				_, err := database.RuntimeEventsAfter(t.Context(), snapshot.Project, foreign)
				if !errors.Is(err, ErrRuntimeCursorExpired) {
					t.Fatalf("database resume accepted another project's cursor: %v", err)
				}
				reason, _, authored := failure.Describe(err)
				if !authored || reason != failure.AppCursorExpired {
					t.Fatalf("cross-project resume lost the authored cursor failure: %v", err)
				}
				if _, err := RuntimeEventsAfter(snapshot, foreign); !errors.Is(err, ErrRuntimeCursorExpired) {
					t.Fatalf("snapshot resume accepted another project's cursor: %v", err)
				}
				if _, err := database.CommitRuntimeUpdate(t.Context(), snapshot.Project, RuntimeUpdate{ExpectedCursor: foreign, Services: []json.RawMessage{}, Type: "cross.project", Payload: json.RawMessage(`{}`)}); !errors.Is(err, ErrRuntimeConflict) {
					t.Fatalf("app update accepted another project's cursor: %v", err)
				}
				unchanged, err := database.ReadRuntimeSnapshot(t.Context(), snapshot.Project)
				if err != nil || unchanged.Cursor != snapshot.Cursor || len(unchanged.Events) != len(snapshot.Events) {
					t.Fatalf("rejected cross-project operations changed state: %#v, %v", unchanged, err)
				}
			}
		})
	}
}

func TestRuntimePublicationEventsMatchCompleteSnapshotObservation(t *testing.T) {
	for _, service := range []string{"", "database"} {
		t.Run("service_"+service, func(t *testing.T) {
			database := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
			database.heartbeatInterval = time.Hour
			started := time.Unix(1700000000, 123456789).UTC()
			now := started
			database.now = func() time.Time { return now }
			project := t.TempDir()
			tunnel, err := database.BeginTunnel(t.Context(), BeginTunnelOptions{
				Command: TunnelCommandPublish, Server: "https://server.example", Target: "5432",
				Project: project, Service: service,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer tunnel.Finish(context.Background(), nil)
			assertCompletePublicationEvent(t, database, project)
			now = now.Add(time.Second)
			if err := tunnel.SetPublicURL(t.Context(), testPublicURLID, "service.example"); err != nil {
				t.Fatal(err)
			}
			assertCompletePublicationEvent(t, database, project)
			now = now.Add(time.Second)
			if err := tunnel.SetProvisioning(t.Context(), 7); err != nil {
				t.Fatal(err)
			}
			before := assertCompletePublicationEvent(t, database, project)
			now = now.Add(time.Second)
			heartbeatAt := now
			rows, err := database.queries.HeartbeatTunnel(t.Context(), clientstatedb.HeartbeatTunnelParams{ID: tunnel.ID(), Now: now.UnixNano(), LeaseExpiresAt: now.Add(tunnelLeaseDuration).UnixNano()})
			if err != nil || rows != 1 {
				t.Fatalf("heartbeat: %d, %v", rows, err)
			}
			after, err := database.ReadRuntimeSnapshot(t.Context(), project)
			if err != nil || after.Cursor != before.Cursor {
				t.Fatalf("heartbeat created an event: %v", err)
			}
			now = now.Add(time.Second)
			publicURL := "https://service.example"
			if err := tunnel.SetReady(t.Context(), publicURL, 7); err != nil {
				t.Fatal(err)
			}
			ready := assertCompletePublicationEvent(t, database, project)
			if !ready.Publications[0].HeartbeatAt.Equal(heartbeatAt) || !ready.Publications[0].LeaseExpiresAt.Equal(heartbeatAt.Add(tunnelLeaseDuration)) {
				t.Fatal("publication lost the heartbeat and lease preceding its mutation")
			}
			now = now.Add(time.Second)
			if err := tunnel.SetDraining(t.Context()); err != nil {
				t.Fatal(err)
			}
			assertCompletePublicationEvent(t, database, project)
			now = now.Add(time.Second)
			if err := tunnel.Finish(t.Context(), nil); err != nil {
				t.Fatal(err)
			}
			terminal, err := database.ReadRuntimeSnapshot(t.Context(), project)
			if err != nil {
				t.Fatal(err)
			}
			var event struct {
				Publication TunnelInfo `json:"publication"`
			}
			if err := json.Unmarshal(terminal.Events[len(terminal.Events)-1].Payload, &event); err != nil {
				t.Fatal(err)
			}
			want := ready.Publications[0]
			want.State, want.UpdatedAt, want.HeartbeatAt, want.LeaseExpiresAt = TunnelStateStopped, now, now, now
			if len(terminal.Publications) != 0 || !reflect.DeepEqual(event.Publication, want) {
				t.Fatalf("terminal event observation = %#v, want %#v", event.Publication, want)
			}
		})
	}
}

func TestRuntimePublicationEventTimestampPrecision(t *testing.T) {
	for _, at := range []time.Time{time.Unix(1700000000, 123000000).UTC(), time.Unix(0, 0).UTC(), time.Unix(0, -1).UTC()} {
		t.Run(at.Format(time.RFC3339Nano), func(t *testing.T) {
			database := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
			database.heartbeatInterval = time.Hour
			database.now = func() time.Time { return at }
			project := t.TempDir()
			tunnel, err := database.BeginTunnel(t.Context(), BeginTunnelOptions{Command: TunnelCommandPublish, Server: "https://server.example", Target: "3000", Project: project})
			if err != nil {
				t.Fatal(err)
			}
			defer tunnel.Finish(context.Background(), nil)
			assertCompletePublicationEvent(t, database, project)
		})
	}
}

func assertCompletePublicationEvent(t *testing.T, database *Database, project string) RuntimeSnapshot {
	t.Helper()
	snapshot, err := database.ReadRuntimeSnapshot(t.Context(), project)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Publications) != 1 || len(snapshot.Events) == 0 {
		t.Fatalf("missing publication observation: %#v", snapshot)
	}
	latest := snapshot.Events[len(snapshot.Events)-1]
	var event struct {
		Publication TunnelInfo `json:"publication"`
	}
	if err := json.Unmarshal(latest.Payload, &event); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(event.Publication, snapshot.Publications[0]) {
		t.Fatalf("event observation = %#v, snapshot observation = %#v", event.Publication, snapshot.Publications[0])
	}
	if event.Publication.ProcessID <= 0 || !event.Publication.UpdatedAt.Equal(latest.At) {
		t.Fatal("publication event omitted its process or mutation time")
	}
	return snapshot
}
