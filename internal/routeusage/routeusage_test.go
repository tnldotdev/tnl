package routeusage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/routes"
	"github.com/tnldotdev/tnl/internal/state"
	"github.com/tnldotdev/tnl/internal/state/statedb"
	"github.com/tnldotdev/tnl/pkg/protocol/routeusagev1"
)

const testRouteID = "route_test"

func TestCollectorSplitsConnectionUsageAcrossMinuteBuckets(t *testing.T) {
	db, store := newTestStore(t)
	collector := NewCollector(store, nil)
	start := time.Date(2026, time.January, 2, 12, 0, 50, 0, time.UTC)

	connection := collector.Open(testRouteID, 1, start)
	connection.AddIngress(100, start.Add(20*time.Second))
	connection.AddEgress(50, start.Add(25*time.Second))
	connection.Close(start.Add(30 * time.Second))
	if err := collector.Checkpoint(t.Context(), start.Add(70*time.Second), true); err != nil {
		t.Fatal(err)
	}

	queries := statedb.New(db)
	firstMinute := loadUsageBucket(t, queries, "minute", start.Truncate(time.Minute))
	secondMinute := loadUsageBucket(t, queries, "minute", start.Add(time.Minute).Truncate(time.Minute))
	hour := loadUsageBucket(t, queries, "hour", start.Truncate(time.Hour))

	assertUsage(t, firstMinute, 1, 10*time.Second, 0, 0, 1, 1)
	assertUsage(t, secondMinute, 0, 20*time.Second, 100, 50, 1, 1)
	assertUsage(t, hour, 1, 30*time.Second, 100, 50, 0, 1)
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_usage_outbox_items WHERE source_kind = 'usage_snapshot'"); count != 3 {
		t.Fatalf("usage outbox count = %d, want 3", count)
	}
}

func TestLifecycleRecordingIsTransactionalAndIdempotent(t *testing.T) {
	db, store := newTestStore(t)
	change := routes.LifecycleChange{
		RouteID: testRouteID, Version: 1, OccurredAt: time.Now(), Transition: routes.LifecycleVersionStarted,
	}

	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordLifecycle(t.Context(), statedb.New(db).WithTx(tx), change); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_lifecycle_events"); count != 0 {
		t.Fatalf("rolled back lifecycle count = %d, want 0", count)
	}

	tx, err = db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	queries := statedb.New(db).WithTx(tx)
	if err := store.RecordLifecycle(t.Context(), queries, change); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordLifecycle(t.Context(), queries, change); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_lifecycle_events"); count != 1 {
		t.Fatalf("lifecycle count = %d, want 1", count)
	}
	if sequence := scalar(t, db, "SELECT lifecycle_sequence FROM routes WHERE id = ?", testRouteID); sequence != 1 {
		t.Fatalf("lifecycle sequence = %d, want 1", sequence)
	}
}

func TestPublisherPrioritizesLifecycleAndDeletesCompletedUsage(t *testing.T) {
	db, store := newTestStore(t)
	start := time.Date(2026, time.January, 2, 12, 0, 0, 0, time.UTC)
	enqueueLifecycle(t, db, store, start)
	if err := store.SaveUsage(t.Context(), []UsageSnapshot{{
		RouteID: testRouteID, Version: 1, Resolution: "minute", BucketStart: start,
		Revision: 1, ObservedThrough: start.Add(time.Minute), Complete: true, Publish: true,
	}}); err != nil {
		t.Fatal(err)
	}

	paths := make(chan string, 2)
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer secret" {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		paths <- request.URL.Path
		response.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(receiver.Close)
	sender, err := NewSender(store, receiver.URL, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}

	for range 2 {
		delivered, err := sender.SendOne(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if !delivered {
			t.Fatal("expected queued report")
		}
	}
	if first, second := <-paths, <-paths; first != "/v1/routes/route_test/lifecycle-events" || second != "/v1/routes/route_test/usage-snapshots" {
		t.Fatalf("delivery order = %q, %q", first, second)
	}
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_usage_outbox_items"); count != 0 {
		t.Fatalf("outbox count = %d, want 0", count)
	}
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_usage_snapshots"); count != 0 {
		t.Fatalf("completed usage count = %d, want 0", count)
	}
}

func TestPublisherAcknowledgesOnlyDeliveredRevision(t *testing.T) {
	db, store := newTestStore(t)
	start := time.Date(2026, time.January, 2, 12, 0, 0, 0, time.UTC)
	first := UsageSnapshot{
		RouteID: testRouteID, Version: 1, Resolution: "hour", BucketStart: start,
		Revision: 1, ObservedThrough: start.Add(time.Minute), IngressBytes: 10, Publish: true,
	}
	if err := store.SaveUsage(t.Context(), []UsageSnapshot{first}); err != nil {
		t.Fatal(err)
	}

	var requests atomic.Int64
	updateErrors := make(chan error, 1)
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var payload routeusagev1.RouteUsageSnapshot
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			updateErrors <- err
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		if requests.Add(1) == 1 {
			second := first
			second.Revision = 2
			second.ObservedThrough = start.Add(2 * time.Minute)
			second.IngressBytes = 20
			updateErrors <- store.SaveUsage(context.Background(), []UsageSnapshot{second})
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(receiver.Close)
	sender, err := NewSender(store, receiver.URL, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}

	if delivered, err := sender.SendOne(t.Context()); err != nil || !delivered {
		t.Fatalf("first publish: delivered=%v err=%v", delivered, err)
	}
	if err := <-updateErrors; err != nil {
		t.Fatal(err)
	}
	if revision := scalar(t, db, "SELECT source_revision FROM route_usage_outbox_items"); revision != 2 {
		t.Fatalf("queued revision = %d, want 2", revision)
	}
	if delivered, err := sender.SendOne(t.Context()); err != nil || !delivered {
		t.Fatalf("second publish: delivered=%v err=%v", delivered, err)
	}
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_usage_outbox_items"); count != 0 {
		t.Fatalf("outbox count = %d, want 0", count)
	}
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_usage_snapshots"); count != 1 {
		t.Fatalf("incomplete usage count = %d, want 1", count)
	}
}

func TestPublisherDoesNotFollowRedirectsOrAcknowledgeFailures(t *testing.T) {
	db, store := newTestStore(t)
	enqueueLifecycle(t, db, store, time.Now())
	var redirected atomic.Bool
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/redirected" {
			redirected.Store(true)
			response.WriteHeader(http.StatusNoContent)
			return
		}
		response.Header().Set("Location", "/redirected")
		response.WriteHeader(http.StatusTemporaryRedirect)
	}))
	t.Cleanup(receiver.Close)
	sender, err := NewSender(store, receiver.URL, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}

	delivered, err := sender.SendOne(t.Context())
	if !delivered || err == nil {
		t.Fatalf("redirect publish: delivered=%v err=%v", delivered, err)
	}
	if redirected.Load() {
		t.Fatal("sender followed redirect")
	}
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_usage_outbox_items"); count != 1 {
		t.Fatalf("outbox count = %d, want 1", count)
	}
}

func TestPublisherPollsTheDurableOutbox(t *testing.T) {
	db, store := newTestStore(t)
	received := make(chan struct{}, 1)
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		received <- struct{}{}
		response.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(receiver.Close)
	observer := &testObserver{outboxObserved: make(chan struct{})}
	sender, err := NewSender(store, receiver.URL, "secret", observer)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		sender.Run(ctx, nil)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()

	select {
	case <-observer.outboxObserved:
	case <-time.After(time.Second):
		t.Fatal("sender did not inspect the empty outbox")
	}
	if _, err := db.ExecContext(t.Context(), `
		INSERT INTO route_lifecycle_events (
			event_id, route_id, version, sequence, occurred_at, transition
		) VALUES ('event_0123456789abcdef0123456789abcdef', 'route_test', 1, 1, 1, 'version_started')
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `
		INSERT INTO route_usage_outbox_items (source_kind, source_id, source_revision, enqueued_at)
		SELECT 'lifecycle_event', id, 1, 1 FROM route_lifecycle_events
	`); err != nil {
		t.Fatal(err)
	}

	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("sender did not poll the durable outbox")
	}
}

func TestCollectorRecoversExpiredBucketAsIncomplete(t *testing.T) {
	db, store := newTestStore(t)
	start := time.Date(2026, time.January, 2, 12, 0, 0, 0, time.UTC)
	if err := store.SaveUsage(t.Context(), []UsageSnapshot{{
		RouteID: testRouteID, Version: 1, Resolution: "minute", BucketStart: start,
		ObservedThrough: start.Add(30 * time.Second), ConnectionNanoseconds: uint64(30 * time.Second),
	}}); err != nil {
		t.Fatal(err)
	}
	collector := NewCollector(store, nil)
	collector.now = func() time.Time { return start.Add(2 * time.Minute) }
	if err := collector.Recover(t.Context()); err != nil {
		t.Fatal(err)
	}

	bucket := loadUsageBucket(t, statedb.New(db), "minute", start)
	assertUsage(t, bucket, 0, 30*time.Second, 0, 0, 0, 1)
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_usage_outbox_items"); count != 1 {
		t.Fatalf("outbox count = %d, want 1", count)
	}
}

func newTestStore(t *testing.T) (*sql.DB, *Store) {
	t.Helper()
	db, err := state.Open(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, statement := range []string{
		"INSERT INTO identities (id, display_name, email, created_at) VALUES ('identity_test', 'Test', 'test@example.com', 1)",
		"INSERT INTO hostnames (id, identity_id, hostname, kind, status, source, created_at, activated_at) VALUES ('hostname_test', 'identity_test', 'test.tnl.dev', 'managed', 'active', 'user', 1, 1)",
		"INSERT INTO routes (id, hostname_id, identity_id, hostname, local_target, status, version, created_at) VALUES ('route_test', 'hostname_test', 'identity_test', 'test.tnl.dev', 'localhost:8080', 'active', 1, 1)",
	} {
		if _, err := db.ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	return db, store
}

func enqueueLifecycle(t *testing.T, db *sql.DB, store *Store, occurredAt time.Time) {
	t.Helper()
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := store.RecordLifecycle(t.Context(), statedb.New(db).WithTx(tx), routes.LifecycleChange{
		RouteID: testRouteID, Version: 1, OccurredAt: occurredAt, Transition: routes.LifecycleVersionStarted,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func loadUsageBucket(t *testing.T, queries *statedb.Queries, resolution string, start time.Time) statedb.RouteUsageSnapshot {
	t.Helper()
	bucket, err := queries.GetRouteUsageSnapshot(t.Context(), statedb.GetRouteUsageSnapshotParams{
		RouteID: testRouteID, Version: 1, Resolution: resolution, BucketStart: start.UnixNano(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return bucket
}

func assertUsage(
	t *testing.T,
	bucket statedb.RouteUsageSnapshot,
	connections int64,
	duration time.Duration,
	ingress int64,
	egress int64,
	complete int64,
	revision int64,
) {
	t.Helper()
	if bucket.ConnectionsOpened != connections ||
		bucket.ConnectionNanoseconds != int64(duration) ||
		bucket.IngressBytes != ingress ||
		bucket.EgressBytes != egress ||
		bucket.Complete != complete ||
		bucket.Revision != revision {
		t.Fatalf("usage bucket = %+v", bucket)
	}
}

func scalar(t *testing.T, db *sql.DB, query string, arguments ...any) int64 {
	t.Helper()
	var value int64
	if err := db.QueryRowContext(t.Context(), query, arguments...).Scan(&value); err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	return value
}

type testObserver struct {
	once           sync.Once
	outboxObserved chan struct{}
}

func (*testObserver) ObserveRouteUsageCheckpoint(string)       {}
func (*testObserver) ObserveRouteUsageDelivery(string, string) {}
func (*testObserver) SetRouteUsageOutbox(string, int64)        {}
func (o *testObserver) SetRouteUsageOldestAge(time.Duration) {
	o.once.Do(func() { close(o.outboxObserved) })
}
