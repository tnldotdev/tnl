package routeexport

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

	"github.com/0xcadams/tnl/internal/routes"
	"github.com/0xcadams/tnl/internal/state"
	"github.com/0xcadams/tnl/internal/state/statedb"
	"github.com/0xcadams/tnl/pkg/protocol/routeexportv1"
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
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_export_outbox WHERE source_kind = 'usage_snapshot'"); count != 3 {
		t.Fatalf("usage outbox count = %d, want 3", count)
	}
}

func TestLifecycleRecordingIsTransactionalAndIdempotent(t *testing.T) {
	db, store := newTestStore(t)
	change := routes.LifecycleChange{
		RouteID: testRouteID, Generation: 1, OccurredAt: time.Now(), Transition: routes.LifecycleGenerationStarted,
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
		RouteID: testRouteID, Generation: 1, Resolution: "minute", BucketStart: start,
		Revision: 1, SourceThrough: start.Add(time.Minute), Complete: true, Publish: true,
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
	publisher, err := NewPublisher(store, receiver.URL, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}

	for range 2 {
		delivered, err := publisher.PublishOne(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if !delivered {
			t.Fatal("expected queued export")
		}
	}
	if first, second := <-paths, <-paths; first != "/v1/routes/route_test/lifecycle-events" || second != "/v1/routes/route_test/usage-snapshots" {
		t.Fatalf("delivery order = %q, %q", first, second)
	}
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_export_outbox"); count != 0 {
		t.Fatalf("outbox count = %d, want 0", count)
	}
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_usage_buckets"); count != 0 {
		t.Fatalf("completed usage count = %d, want 0", count)
	}
}

func TestPublisherAcknowledgesOnlyDeliveredRevision(t *testing.T) {
	db, store := newTestStore(t)
	start := time.Date(2026, time.January, 2, 12, 0, 0, 0, time.UTC)
	first := UsageSnapshot{
		RouteID: testRouteID, Generation: 1, Resolution: "hour", BucketStart: start,
		Revision: 1, SourceThrough: start.Add(time.Minute), IngressBytes: 10, Publish: true,
	}
	if err := store.SaveUsage(t.Context(), []UsageSnapshot{first}); err != nil {
		t.Fatal(err)
	}

	var requests atomic.Int64
	updateErrors := make(chan error, 1)
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var payload routeexportv1.RouteUsageSnapshot
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			updateErrors <- err
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		if requests.Add(1) == 1 {
			second := first
			second.Revision = 2
			second.SourceThrough = start.Add(2 * time.Minute)
			second.IngressBytes = 20
			updateErrors <- store.SaveUsage(context.Background(), []UsageSnapshot{second})
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(receiver.Close)
	publisher, err := NewPublisher(store, receiver.URL, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}

	if delivered, err := publisher.PublishOne(t.Context()); err != nil || !delivered {
		t.Fatalf("first publish: delivered=%v err=%v", delivered, err)
	}
	if err := <-updateErrors; err != nil {
		t.Fatal(err)
	}
	if revision := scalar(t, db, "SELECT source_revision FROM route_export_outbox"); revision != 2 {
		t.Fatalf("queued revision = %d, want 2", revision)
	}
	if delivered, err := publisher.PublishOne(t.Context()); err != nil || !delivered {
		t.Fatalf("second publish: delivered=%v err=%v", delivered, err)
	}
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_export_outbox"); count != 0 {
		t.Fatalf("outbox count = %d, want 0", count)
	}
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_usage_buckets"); count != 1 {
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
	publisher, err := NewPublisher(store, receiver.URL, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}

	delivered, err := publisher.PublishOne(t.Context())
	if !delivered || err == nil {
		t.Fatalf("redirect publish: delivered=%v err=%v", delivered, err)
	}
	if redirected.Load() {
		t.Fatal("publisher followed redirect")
	}
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_export_outbox"); count != 1 {
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
	publisher, err := NewPublisher(store, receiver.URL, "secret", observer)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		publisher.Run(ctx, nil)
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()

	select {
	case <-observer.outboxObserved:
	case <-time.After(time.Second):
		t.Fatal("publisher did not inspect the empty outbox")
	}
	if _, err := db.ExecContext(t.Context(), `
		INSERT INTO route_lifecycle_events (
			event_id, route_id, generation, sequence, occurred_at_ns, transition
		) VALUES ('event_0123456789abcdef0123456789abcdef', 'route_test', 1, 1, 1, 'generation_started')
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `
		INSERT INTO route_export_outbox (source_kind, source_id, source_revision, created_at_ns)
		SELECT 'lifecycle_event', id, 1, 1 FROM route_lifecycle_events
	`); err != nil {
		t.Fatal(err)
	}

	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("publisher did not poll the durable outbox")
	}
}

func TestCollectorRecoversExpiredBucketAsIncomplete(t *testing.T) {
	db, store := newTestStore(t)
	start := time.Date(2026, time.January, 2, 12, 0, 0, 0, time.UTC)
	if err := store.SaveUsage(t.Context(), []UsageSnapshot{{
		RouteID: testRouteID, Generation: 1, Resolution: "minute", BucketStart: start,
		SourceThrough: start.Add(30 * time.Second), ConnectionNS: uint64(30 * time.Second),
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
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_export_outbox"); count != 1 {
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
		"INSERT INTO principals (id, display_name, email, created_at) VALUES ('principal_test', 'Test', 'test@example.com', 1)",
		"INSERT INTO hostname_claims (id, principal_id, hostname, created_at) VALUES ('claim_test', 'principal_test', 'test.tnl.dev', 1)",
		"INSERT INTO routes (id, claim_id, principal_id, hostname, display_target, state, generation, created_at) VALUES ('route_test', 'claim_test', 'principal_test', 'test.tnl.dev', 'localhost:8080', 'active', 1, 1)",
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
		RouteID: testRouteID, Generation: 1, OccurredAt: occurredAt, Transition: routes.LifecycleGenerationStarted,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func loadUsageBucket(t *testing.T, queries *statedb.Queries, resolution string, start time.Time) statedb.RouteUsageBucket {
	t.Helper()
	bucket, err := queries.GetRouteUsageBucket(t.Context(), statedb.GetRouteUsageBucketParams{
		RouteID: testRouteID, Generation: 1, Resolution: resolution, BucketStartNs: start.UnixNano(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return bucket
}

func assertUsage(
	t *testing.T,
	bucket statedb.RouteUsageBucket,
	connections int64,
	duration time.Duration,
	ingress int64,
	egress int64,
	complete int64,
	revision int64,
) {
	t.Helper()
	if bucket.ConnectionsOpened != connections ||
		bucket.ConnectionNs != int64(duration) ||
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

func (*testObserver) ObserveRouteExportCheckpoint(string)       {}
func (*testObserver) ObserveRouteExportDelivery(string, string) {}
func (*testObserver) SetRouteExportOutbox(string, int64)        {}
func (o *testObserver) SetRouteExportOldestAge(time.Duration) {
	o.once.Do(func() { close(o.outboxObserved) })
}
