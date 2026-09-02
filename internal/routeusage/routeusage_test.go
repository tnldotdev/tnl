package routeusage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
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

const (
	testSignedRouteA = "route_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testSignedRouteB = "route_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestCollectorSplitsConnectionUsageAcrossMinuteBuckets(t *testing.T) {
	db, store := newTestStore(t)
	collector := NewCollector(store, nil)
	start := time.Date(2026, time.January, 2, 12, 0, 50, 0, time.UTC)

	connection := collector.Open(testRouteID, 1, netip.MustParseAddr("192.0.2.1"), start)
	connection.PublisherOpening(start)
	connection.PublisherOpened(start)
	connection.StreamOpened(start)
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

func TestCollectorRecordsAttemptOutcomesAndHistograms(t *testing.T) {
	db, store := newTestStore(t)
	store.visitorMasterSecret = [32]byte{1, 2, 3, 4}
	collector := NewCollector(store, nil)
	start := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)

	policy := collector.Open(testRouteID, 1, netip.MustParseAddr("192.0.2.1"), start)
	policy.PolicyDenied(start.Add(time.Millisecond))
	policy.Close(start.Add(2 * time.Millisecond))
	capacity := collector.Open(testRouteID, 1, netip.MustParseAddr("192.0.2.2"), start.Add(time.Second))
	capacity.CapacityDenied(start.Add(time.Second + time.Millisecond))
	capacity.Close(start.Add(time.Second + 2*time.Millisecond))
	failed := collector.Open(testRouteID, 1, netip.MustParseAddr("2001:db8:1::1"), start.Add(2*time.Second))
	failed.PublisherOpening(start.Add(2 * time.Second))
	failed.PublisherOpenFailed(start.Add(2*time.Second + 25*time.Millisecond))
	failed.Close(start.Add(2*time.Second + 26*time.Millisecond))
	successful := collector.Open(testRouteID, 1, netip.MustParseAddr("2001:db8:2::1"), start.Add(3*time.Second))
	successful.PublisherOpening(start.Add(3 * time.Second))
	successful.PublisherOpened(start.Add(3*time.Second + 80*time.Millisecond))
	successful.StreamOpened(start.Add(3*time.Second + 100*time.Millisecond))
	successful.AddEgress(50, start.Add(3*time.Second+250*time.Millisecond))
	successful.AddIngress(100, start.Add(4*time.Second))
	successful.Close(start.Add(48*time.Second + 100*time.Millisecond))

	if err := collector.Checkpoint(t.Context(), start.Add(70*time.Second), true); err != nil {
		t.Fatal(err)
	}
	bucket := loadUsageBucket(t, statedb.New(db), "minute", start)
	if bucket.ConnectionAttempts != 4 || bucket.PolicyDenials != 1 || bucket.CapacityDenials != 1 ||
		bucket.PublisherOpenFailures != 1 || bucket.SuccessfulStreams != 1 ||
		bucket.ConnectionNanoseconds != int64(45*time.Second) || bucket.IngressBytes != 100 || bucket.EgressBytes != 50 {
		t.Fatalf("usage counters = %+v", bucket)
	}
	openHistogram := decodeTestHistogram(t, bucket.PublisherOpenLatency)
	if openHistogram.count() != 2 || openHistogram.sumNanoseconds != uint64(105*time.Millisecond) ||
		openHistogram.counts[2] != 0 || openHistogram.counts[3] != 1 || openHistogram.counts[5] != 2 {
		t.Fatalf("publisher open histogram = %+v", openHistogram)
	}
	firstByteHistogram := decodeTestHistogram(t, bucket.TimeToFirstPublisherByte)
	if firstByteHistogram.count() != 1 || firstByteHistogram.sumNanoseconds != uint64(250*time.Millisecond) ||
		firstByteHistogram.counts[5] != 0 || firstByteHistogram.counts[6] != 1 {
		t.Fatalf("time to first publisher byte histogram = %+v", firstByteHistogram)
	}
	durationHistogram := decodeTestHistogram(t, bucket.SuccessfulConnectionDuration)
	if durationHistogram.count() != 1 || durationHistogram.sumNanoseconds != uint64(45*time.Second) ||
		durationHistogram.counts[12] != 0 || durationHistogram.counts[13] != 1 {
		t.Fatalf("successful connection duration histogram = %+v", durationHistogram)
	}
	expectedVisitors := new(visitorSketch)
	for _, source := range []string{"192.0.2.1", "192.0.2.2", "2001:db8:1::1", "2001:db8:2::1"} {
		hash, ok := visitorNetworkHash(store.visitorMasterSecret, testRouteID, netip.MustParseAddr(source), start)
		if !ok {
			t.Fatalf("visitor source %s was invalid", source)
		}
		expectedVisitors.insert(hash)
	}
	if bucket.VisitorNetworkEstimate != int64(expectedVisitors.estimate()) ||
		!bytes.Equal(bucket.VisitorNetworkHll, expectedVisitors.checkpoint()) {
		t.Fatalf("visitor checkpoint estimate=%d data=%x", bucket.VisitorNetworkEstimate, bucket.VisitorNetworkHll)
	}
}

func TestCollectorLeavesUnobservedHistogramsUndefined(t *testing.T) {
	db, store := newTestStore(t)
	collector := NewCollector(store, nil)
	start := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	connection := collector.Open(testRouteID, 1, netip.MustParseAddr("192.0.2.1"), start)
	connection.PolicyDenied(start)
	connection.Close(start)
	if err := collector.Checkpoint(t.Context(), start.Add(time.Minute), true); err != nil {
		t.Fatal(err)
	}
	bucket := loadUsageBucket(t, statedb.New(db), "minute", start)
	if bucket.PublisherOpenLatency != nil || bucket.TimeToFirstPublisherByte != nil ||
		bucket.SuccessfulConnectionDuration != nil {
		t.Fatalf("unobserved histograms are defined: %+v", bucket)
	}
}

func TestCollectorPublishesHoursOnlyWhenFinalized(t *testing.T) {
	db, store := newTestStore(t)
	collector := NewCollector(store, nil)
	start := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	connection := collector.Open(testRouteID, 1, netip.MustParseAddr("192.0.2.1"), start)
	connection.PolicyDenied(start)
	connection.Close(start)

	if err := collector.Checkpoint(t.Context(), start.Add(time.Minute), false); err != nil {
		t.Fatal(err)
	}
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_usage_outbox_items WHERE source_kind = 'usage_snapshot'"); count != 1 {
		t.Fatalf("outbox count after minute = %d, want 1", count)
	}
	hour := loadUsageBucket(t, statedb.New(db), "hour", start)
	if hour.Finalized != 0 || hour.Complete != 0 {
		t.Fatalf("active hour state = %+v", hour)
	}

	if err := collector.Checkpoint(t.Context(), start.Add(time.Hour), false); err != nil {
		t.Fatal(err)
	}
	hour = loadUsageBucket(t, statedb.New(db), "hour", start)
	if hour.Finalized != 1 || hour.Complete != 1 {
		t.Fatalf("completed hour state = %+v", hour)
	}
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_usage_outbox_items WHERE source_kind = 'usage_snapshot'"); count != 2 {
		t.Fatalf("outbox count after hour = %d, want 2", count)
	}
}

func TestCollectorFinalizesCurrentHourAsPartial(t *testing.T) {
	db, store := newTestStore(t)
	collector := NewCollector(store, nil)
	start := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	connection := collector.Open(testRouteID, 1, netip.MustParseAddr("192.0.2.1"), start)
	connection.PolicyDenied(start)
	connection.Close(start)
	if err := collector.Checkpoint(t.Context(), start.Add(30*time.Second), true); err != nil {
		t.Fatal(err)
	}
	hour := loadUsageBucket(t, statedb.New(db), "hour", start)
	if hour.Finalized != 1 || hour.Complete != 0 || hour.ObservedThrough != start.Add(30*time.Second).UnixNano() {
		t.Fatalf("partial hour state = %+v", hour)
	}
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_usage_outbox_items WHERE source_kind = 'usage_snapshot'"); count != 1 {
		t.Fatalf("partial hour outbox count = %d, want 1", count)
	}
}

func TestDurationHistogramIncludesMultiDayBounds(t *testing.T) {
	var histogram durationHistogram
	for _, duration := range []time.Duration{24 * time.Hour, 3 * 24 * time.Hour, 7 * 24 * time.Hour, 7*24*time.Hour + 1} {
		if !histogram.observe(duration) {
			t.Fatalf("observe %s", duration)
		}
	}
	if durationHistogramSize != 184 || len(histogram.counts) != 22 {
		t.Fatalf("histogram size=%d buckets=%d", durationHistogramSize, len(histogram.counts))
	}
	if histogram.counts[18] != 1 || histogram.counts[19] != 2 || histogram.counts[20] != 3 || histogram.counts[21] != 4 {
		t.Fatalf("multi-day cumulative counts = %v", histogram.counts[18:])
	}
	if _, err := unmarshalDurationHistogram(histogram.marshalBinary()); err != nil {
		t.Fatal(err)
	}
}

func TestCollectorRecordsPublisherSetupFailureAfterOpen(t *testing.T) {
	db, store := newTestStore(t)
	collector := NewCollector(store, nil)
	start := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	connection := collector.Open(testRouteID, 1, netip.MustParseAddr("192.0.2.1"), start)
	connection.PublisherOpening(start)
	connection.PublisherOpened(start.Add(10 * time.Millisecond))
	connection.PublisherOpenFailed(start.Add(20 * time.Millisecond))
	connection.StreamOpened(start.Add(30 * time.Millisecond))
	connection.Close(start.Add(40 * time.Millisecond))
	if err := collector.Checkpoint(t.Context(), start.Add(time.Minute), true); err != nil {
		t.Fatal(err)
	}

	bucket := loadUsageBucket(t, statedb.New(db), "minute", start)
	if bucket.ConnectionAttempts != 1 || bucket.PublisherOpenFailures != 1 || bucket.SuccessfulStreams != 0 {
		t.Fatalf("usage funnel = %+v", bucket)
	}
	histogram := decodeTestHistogram(t, bucket.PublisherOpenLatency)
	if histogram.count() != 1 || histogram.sumNanoseconds != uint64(10*time.Millisecond) {
		t.Fatalf("publisher open histogram = %+v", histogram)
	}
}

func TestVisitorNetworkHashNormalizesAndRotates(t *testing.T) {
	secret := [32]byte{1, 2, 3, 4}
	at := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	hash := func(routeID, source string, when time.Time) uint64 {
		t.Helper()
		value, ok := visitorNetworkHash(secret, routeID, netip.MustParseAddr(source), when)
		if !ok {
			t.Fatalf("visitor source %s was invalid", source)
		}
		return value
	}
	if hash(testRouteID, "192.0.2.1", at) != hash(testRouteID, "::ffff:192.0.2.1", at) {
		t.Fatal("IPv4 and mapped IPv4 were not normalized to the same /32")
	}
	if hash(testRouteID, "2001:db8:1::1", at) != hash(testRouteID, "2001:db8:1::ffff", at) {
		t.Fatal("IPv6 addresses in one /64 did not share an identity")
	}
	base := hash(testRouteID, "2001:db8:1::1", at)
	if base == hash(testRouteID, "2001:db8:2::1", at) ||
		base == hash("route_other", "2001:db8:1::1", at) ||
		base == hash(testRouteID, "2001:db8:1::1", at.Add(24*time.Hour)) {
		t.Fatal("visitor identity was not separated by network, route, and UTC day")
	}
}

func TestVisitorSketchIsSharedAcrossVersionsAndRecovery(t *testing.T) {
	db, store := newTestStore(t)
	start := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	collector := NewCollector(store, nil)
	for version, source := range []string{"2001:db8:1::1", "2001:db8:1::ffff"} {
		connection := collector.Open(testRouteID, uint64(version+1), netip.MustParseAddr(source), start.Add(time.Duration(version)*time.Second))
		connection.PolicyDenied(start.Add(time.Duration(version) * time.Second))
		connection.Close(start.Add(time.Duration(version) * time.Second))
	}
	if err := collector.Checkpoint(t.Context(), start.Add(10*time.Second), false); err != nil {
		t.Fatal(err)
	}
	first := loadUsageBucketVersion(t, statedb.New(db), 1, "hour", start)
	second := loadUsageBucketVersion(t, statedb.New(db), 2, "hour", start)
	if first.VisitorNetworkEstimate != 1 || second.VisitorNetworkEstimate != 1 ||
		!bytes.Equal(first.VisitorNetworkHll, second.VisitorNetworkHll) {
		t.Fatalf("version visitor sketches differ: first=%+v second=%+v", first, second)
	}

	restartedStore, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if restartedStore.visitorMasterSecret != store.visitorMasterSecret {
		t.Fatal("visitor master secret changed across store restart")
	}
	restarted := NewCollector(restartedStore, nil)
	restarted.now = func() time.Time { return start.Add(20 * time.Second) }
	if err := restarted.Recover(t.Context()); err != nil {
		t.Fatal(err)
	}
	firstHash, _ := visitorNetworkHash(store.visitorMasterSecret, testRouteID, netip.MustParseAddr("2001:db8:1::1"), start)
	newSource := netip.Addr{}
	for _, candidate := range []string{"2001:db8:2::1", "2001:db8:3::1", "2001:db8:4::1"} {
		source := netip.MustParseAddr(candidate)
		hash, _ := visitorNetworkHash(store.visitorMasterSecret, testRouteID, source, start)
		if hash>>(64-visitorHLLPrecision) != firstHash>>(64-visitorHLLPrecision) {
			newSource = source
			break
		}
	}
	if !newSource.IsValid() {
		t.Fatal("test visitor candidates unexpectedly occupied one HLL register")
	}
	connection := restarted.Open(testRouteID, 3, newSource, start.Add(21*time.Second))
	connection.PolicyDenied(start.Add(21 * time.Second))
	connection.Close(start.Add(21 * time.Second))
	if err := restarted.Checkpoint(t.Context(), start.Add(30*time.Second), false); err != nil {
		t.Fatal(err)
	}
	for version := uint64(1); version <= 3; version++ {
		bucket := loadUsageBucketVersion(t, statedb.New(db), version, "hour", start)
		if bucket.VisitorNetworkEstimate != 2 {
			t.Fatalf("version %d visitor estimate = %d, want 2", version, bucket.VisitorNetworkEstimate)
		}
	}
	updatedFirst := loadUsageBucketVersion(t, statedb.New(db), 1, "hour", start)
	updatedSecond := loadUsageBucketVersion(t, statedb.New(db), 2, "hour", start)
	third := loadUsageBucketVersion(t, statedb.New(db), 3, "hour", start)
	if !bytes.Equal(updatedFirst.VisitorNetworkHll, updatedSecond.VisitorNetworkHll) ||
		!bytes.Equal(updatedFirst.VisitorNetworkHll, third.VisitorNetworkHll) {
		t.Fatal("recovered route versions do not share one visitor sketch")
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

func TestRouteRegistrationAndInitialLifecycleAreTransactional(t *testing.T) {
	db, store := newTestStore(t)
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(t.Context(), signedRouteInsertSQL,
		testSignedRouteA, "a.example", testAuthorizationID("a"), "key-a", testRetryID("a"),
	); err != nil {
		t.Fatal(err)
	}
	queries := statedb.New(db).WithTx(tx)
	registration := testRegistration(testSignedRouteA, "a.example", "a")
	if err := store.RecordRegistration(t.Context(), queries, registration); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordLifecycle(t.Context(), queries, routes.LifecycleChange{
		RouteID: testSignedRouteA, Version: 1, OccurredAt: registration.CreatedAt,
		Transition: routes.LifecycleVersionStarted,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name  string
		query string
	}{
		{name: "route", query: "SELECT COUNT(*) FROM routes WHERE id = '" + testSignedRouteA + "'"},
		{name: "registration", query: "SELECT COUNT(*) FROM route_registrations"},
		{name: "lifecycle", query: "SELECT COUNT(*) FROM route_lifecycle_events"},
		{name: "outbox", query: "SELECT COUNT(*) FROM route_usage_outbox_items"},
	}
	for _, check := range checks {
		if count := scalar(t, db, check.query); count != 0 {
			t.Fatalf("rolled back %s count = %d, want 0", check.name, count)
		}
	}
}

func TestSenderDeliversRegistrationBeforeRouteReports(t *testing.T) {
	db, store := newTestStore(t)
	insertSignedTestRoute(t, db, testSignedRouteA, "a.example", "a")
	enqueueRegistration(t, db, store, testSignedRouteA, "a.example", "a")
	enqueueRouteLifecycle(t, db, store, testSignedRouteA, routes.LifecycleVersionStarted, time.Now())
	start := time.Date(2026, time.January, 2, 12, 0, 0, 0, time.UTC)
	if err := store.SaveUsage(t.Context(), []UsageSnapshot{{
		RouteID: testSignedRouteA, Version: 1, Resolution: "minute", BucketStart: start,
		Revision: 1, ObservedThrough: start.Add(time.Minute), Publish: true,
	}}); err != nil {
		t.Fatal(err)
	}

	paths := make(chan string, 3)
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		paths <- request.URL.Path
		acceptRouteUsageRequest(response, request)
	}))
	t.Cleanup(receiver.Close)
	sender, err := NewSender(store, receiver.URL, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if delivered, err := sender.SendOne(t.Context()); err != nil || !delivered {
			t.Fatalf("send: delivered=%v err=%v", delivered, err)
		}
	}
	want := []string{
		"/v1/routes",
		"/v1/routes/lifecycle-events",
		"/v1/routes/usage-snapshots",
	}
	for index, expected := range want {
		if got := <-paths; got != expected {
			t.Fatalf("request %d path = %q, want %q", index, got, expected)
		}
	}
	if revision := scalar(t, db, "SELECT acknowledged_revision FROM route_registrations WHERE route_id = ?", testSignedRouteA); revision != 1 {
		t.Fatalf("acknowledged registration revision = %d, want 1", revision)
	}
}

func TestWireTimestampUTCNormalizesAndTruncates(t *testing.T) {
	location := time.FixedZone("test", -7*60*60)
	tests := []struct {
		name  string
		input time.Time
		want  string
	}{
		{
			name:  "milliseconds",
			input: time.Date(2026, time.September, 2, 5, 0, 0, 123456789, location),
			want:  "2026-09-02T12:00:00.123Z",
		},
		{
			name:  "whole second",
			input: time.Date(2026, time.September, 2, 5, 0, 0, 999999, location),
			want:  "2026-09-02T12:00:00Z",
		},
		{
			name:  "before bucket boundary",
			input: time.Date(2026, time.September, 2, 5, 0, 59, 999999999, location),
			want:  "2026-09-02T12:00:59.999Z",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := wireTimestamp(test.input)
			if got.Location() != time.UTC {
				t.Fatalf("location = %v, want UTC", got.Location())
			}
			encoded, err := got.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			if string(encoded) != `"`+test.want+`"` {
				t.Fatalf("wire timestamp = %s, want %q", encoded, test.want)
			}
		})
	}
}

func TestSenderFormatsAllWireTimestamps(t *testing.T) {
	db, store := newTestStore(t)
	insertSignedTestRoute(t, db, testSignedRouteA, "a.example", "a")
	location := time.FixedZone("test", -7*60*60)
	createdAt := time.Date(2026, time.September, 2, 5, 0, 0, 123456789, location)
	enqueueRegistration(t, db, store, testSignedRouteA, "a.example", "a")
	if _, err := db.ExecContext(t.Context(),
		"UPDATE route_registrations SET created_at = ? WHERE route_id = ?",
		createdAt.UTC().UnixNano(), testSignedRouteA,
	); err != nil {
		t.Fatal(err)
	}
	occurredAt := time.Date(2026, time.September, 2, 5, 1, 0, 987654321, location)
	enqueueRouteLifecycle(t, db, store, testSignedRouteA, routes.LifecycleVersionStarted, occurredAt)
	bucketStart := time.Date(2026, time.September, 2, 5, 2, 0, 999999, location)
	observedThrough := time.Date(2026, time.September, 2, 5, 2, 59, 999999999, location)
	if err := store.SaveUsage(t.Context(), []UsageSnapshot{{
		RouteID: testSignedRouteA, Version: 1, Resolution: "minute", BucketStart: bucketStart,
		Revision: 1, ObservedThrough: observedThrough, Publish: true,
	}}); err != nil {
		t.Fatal(err)
	}

	type receivedRequest struct {
		path string
		body []byte
	}
	received := make(chan receivedRequest, 3)
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		received <- receivedRequest{path: request.URL.Path, body: body}
		if request.URL.Path == "/v1/routes" {
			response.WriteHeader(http.StatusNoContent)
		} else {
			writeAcceptedBatchResponse(response, body)
		}
	}))
	t.Cleanup(receiver.Close)
	sender, err := NewSender(store, receiver.URL, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if delivered, err := sender.SendOne(t.Context()); err != nil || !delivered {
			t.Fatalf("send: delivered=%v err=%v", delivered, err)
		}
	}

	want := map[string]map[string]string{
		"/v1/routes": {
			"created_at": "2026-09-02T12:00:00.123Z",
		},
		"/v1/routes/lifecycle-events": {
			"occurred_at": "2026-09-02T12:01:00.987Z",
		},
		"/v1/routes/usage-snapshots": {
			"bucket_start":     "2026-09-02T12:02:00Z",
			"observed_through": "2026-09-02T12:02:59.999Z",
		},
	}
	for range 3 {
		request := <-received
		var payload map[string]json.RawMessage
		if err := json.Unmarshal(request.body, &payload); err != nil {
			t.Fatal(err)
		}
		if request.path != "/v1/routes" {
			var items []map[string]json.RawMessage
			if err := json.Unmarshal(payload["items"], &items); err != nil || len(items) != 1 {
				t.Fatalf("decode %s batch: items=%d err=%v", request.path, len(items), err)
			}
			payload = items[0]
		}
		for field, expected := range want[request.path] {
			var got string
			if err := json.Unmarshal(payload[field], &got); err != nil {
				t.Fatalf("decode %s %s: %v", request.path, field, err)
			}
			if got != expected {
				t.Errorf("%s %s = %q, want %q", request.path, field, got, expected)
			}
		}
		delete(want, request.path)
	}
	if len(want) != 0 {
		t.Fatalf("missing requests: %v", want)
	}
	var storedBucketStart int64
	if err := db.QueryRowContext(t.Context(),
		"SELECT bucket_start FROM route_usage_snapshots WHERE route_id = ?", testSignedRouteA,
	).Scan(&storedBucketStart); err != nil {
		t.Fatal(err)
	}
	if storedBucketStart != bucketStart.UTC().UnixNano() {
		t.Fatalf("stored bucket start = %d, want %d", storedBucketStart, bucketStart.UTC().UnixNano())
	}
}

func TestFailedRegistrationBlocksOnlyItsRoute(t *testing.T) {
	db, store := newTestStore(t)
	insertSignedTestRoute(t, db, testSignedRouteA, "a.example", "a")
	insertSignedTestRoute(t, db, testSignedRouteB, "b.example", "b")
	enqueueRegistration(t, db, store, testSignedRouteA, "a.example", "a")
	enqueueRouteLifecycle(t, db, store, testSignedRouteA, routes.LifecycleVersionStarted, time.Now())
	start := time.Date(2026, time.January, 2, 12, 0, 0, 0, time.UTC)
	if err := store.SaveUsage(t.Context(), []UsageSnapshot{{
		RouteID: testSignedRouteA, Version: 1, Resolution: "minute", BucketStart: start,
		Revision: 1, ObservedThrough: start.Add(time.Minute), Publish: true,
	}}); err != nil {
		t.Fatal(err)
	}
	enqueueRegistration(t, db, store, testSignedRouteB, "b.example", "b")
	enqueueRouteLifecycle(t, db, store, testSignedRouteB, routes.LifecycleVersionStarted, time.Now())

	paths := make(chan string, 3)
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		paths <- request.URL.Path
		if request.URL.Path == "/v1/routes" {
			var registration routeusagev1.RouteRegistration
			if err := json.NewDecoder(request.Body).Decode(&registration); err != nil {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			if registration.RouteId == testSignedRouteA {
				response.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			response.WriteHeader(http.StatusNoContent)
			return
		}
		acceptRouteUsageRequest(response, request)
	}))
	t.Cleanup(receiver.Close)
	sender, err := NewSender(store, receiver.URL, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	if delivered, err := sender.SendOne(t.Context()); !delivered || err == nil {
		t.Fatalf("failed registration: delivered=%v err=%v", delivered, err)
	}
	for range 2 {
		if delivered, err := sender.SendOne(t.Context()); err != nil || !delivered {
			t.Fatalf("other route send: delivered=%v err=%v", delivered, err)
		}
	}
	if first, second, third := <-paths, <-paths, <-paths; first != "/v1/routes" || second != "/v1/routes" ||
		third != "/v1/routes/lifecycle-events" {
		t.Fatalf("delivery order = %q, %q, %q", first, second, third)
	}
	if count := scalar(t, db, `
		SELECT COUNT(*)
		FROM route_usage_outbox_items AS outbox
		WHERE (outbox.source_kind = 'registration' AND outbox.source_id = (
			SELECT id FROM route_registrations WHERE route_id = ?
		)) OR (outbox.source_kind = 'lifecycle_event' AND outbox.source_id IN (
			SELECT id FROM route_lifecycle_events WHERE route_id = ?
		))
		OR (outbox.source_kind = 'usage_snapshot' AND outbox.source_id IN (
			SELECT id FROM route_usage_snapshots WHERE route_id = ?
		))
	`, testSignedRouteA, testSignedRouteA, testSignedRouteA); count != 3 {
		t.Fatalf("blocked route outbox count = %d, want 3", count)
	}
}

func TestRegistrationRetryPayloadIsIdentical(t *testing.T) {
	db, store := newTestStore(t)
	insertSignedTestRoute(t, db, testSignedRouteA, "a.example", "a")
	enqueueRegistration(t, db, store, testSignedRouteA, "a.example", "a")
	bodies := make(chan []byte, 2)
	var attempts atomic.Int64
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		bodies <- body
		if attempts.Add(1) == 1 {
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(receiver.Close)
	sender, err := NewSender(store, receiver.URL, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	if delivered, err := sender.SendOne(t.Context()); !delivered || err == nil {
		t.Fatalf("first attempt: delivered=%v err=%v", delivered, err)
	}
	if delivered, err := sender.SendOne(t.Context()); err != nil || !delivered {
		t.Fatalf("retry: delivered=%v err=%v", delivered, err)
	}
	if first, second := <-bodies, <-bodies; !bytes.Equal(first, second) {
		t.Fatalf("registration retry payload changed:\nfirst:  %s\nsecond: %s", first, second)
	}
}

func TestUsageRetryRevisionIdentifiesImmutablePayload(t *testing.T) {
	db, store := newTestStore(t)
	acknowledgeVersionStarted(t, db, store)
	start := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	first := UsageSnapshot{
		RouteID: testRouteID, Version: 1, Resolution: "hour", BucketStart: start,
		Revision: 1, ObservedThrough: start.Add(time.Minute), IngressBytes: 10, Publish: true,
	}
	if err := store.SaveUsage(t.Context(), []UsageSnapshot{first}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveUsage(t.Context(), []UsageSnapshot{first}); err != nil {
		t.Fatalf("idempotent revision retry: %v", err)
	}

	bodies := make(chan []byte, 3)
	var attempts atomic.Int64
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		bodies <- body
		if attempts.Add(1) == 1 {
			connection, _, err := response.(http.Hijacker).Hijack()
			if err == nil {
				_ = connection.Close()
			}
			return
		}
		writeAcceptedBatchResponse(response, body)
	}))
	t.Cleanup(receiver.Close)
	sender, err := NewSender(store, receiver.URL, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	if delivered, err := sender.SendOne(t.Context()); !delivered || err == nil {
		t.Fatalf("accepted response loss: delivered=%v err=%v", delivered, err)
	}

	changed := first
	changed.ObservedThrough = start.Add(2 * time.Minute)
	changed.IngressBytes = 20
	changed.Publish = false
	if err := store.SaveUsage(t.Context(), []UsageSnapshot{changed}); err != nil {
		t.Fatal(err)
	}
	changedSameRevision := changed
	changedSameRevision.Publish = true
	if err := store.SaveUsage(t.Context(), []UsageSnapshot{changedSameRevision}); err == nil {
		t.Fatal("changed payload was accepted under revision 1")
	}
	if delivered, err := sender.SendOne(t.Context()); err != nil || !delivered {
		t.Fatalf("retry: delivered=%v err=%v", delivered, err)
	}
	accepted, retry := <-bodies, <-bodies
	if !bytes.Equal(accepted, retry) {
		t.Fatalf("usage retry payload changed under revision 1:\naccepted: %s\nretry:    %s", accepted, retry)
	}

	changed.Revision = 2
	changed.Publish = true
	if err := store.SaveUsage(t.Context(), []UsageSnapshot{changed}); err != nil {
		t.Fatal(err)
	}
	if delivered, err := sender.SendOne(t.Context()); err != nil || !delivered {
		t.Fatalf("changed publish: delivered=%v err=%v", delivered, err)
	}
	var changedPayload routeusagev1.RouteUsageSnapshotBatch
	if err := json.Unmarshal(<-bodies, &changedPayload); err != nil {
		t.Fatal(err)
	}
	if len(changedPayload.Items) != 1 || changedPayload.Items[0].Revision != "2" || changedPayload.Items[0].IngressBytes != "20" {
		t.Fatalf("changed usage payload = %+v", changedPayload)
	}
	var acceptedPayload routeusagev1.RouteUsageSnapshotBatch
	if err := json.Unmarshal(accepted, &acceptedPayload); err != nil {
		t.Fatal(err)
	}
	if acceptedPayload.Items[0].ItemId == changedPayload.Items[0].ItemId {
		t.Fatal("usage report ID did not change with the revision")
	}
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_usage_outbox_items"); count != 0 {
		t.Fatalf("outbox count = %d, want 0", count)
	}
}

func TestRegistrationDeliverySurvivesStoreRestart(t *testing.T) {
	dir := t.TempDir()
	db, err := state.Open(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	insertSignedTestRoute(t, db, testSignedRouteA, "a.example", "a")
	enqueueRegistration(t, db, store, testSignedRouteA, "a.example", "a")
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = state.Open(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	restarted, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan routeusagev1.RouteRegistration, 1)
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var registration routeusagev1.RouteRegistration
		if err := json.NewDecoder(request.Body).Decode(&registration); err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		received <- registration
		response.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(receiver.Close)
	sender, err := NewSender(restarted, receiver.URL, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	if delivered, err := sender.SendOne(t.Context()); err != nil || !delivered {
		t.Fatalf("send after restart: delivered=%v err=%v", delivered, err)
	}
	if registration := <-received; registration.RouteId != testSignedRouteA || registration.RetryId != testRetryID("a") {
		t.Fatalf("registration after restart = %#v", registration)
	}
}

func TestLifecycleDeliveryUsesRouteSequenceNotEnqueueTime(t *testing.T) {
	db, store := newTestStore(t)
	enqueueRouteLifecycle(t, db, store, testRouteID, routes.LifecycleVersionStarted, time.Now())
	enqueueRouteLifecycle(t, db, store, testRouteID, routes.LifecycleReady, time.Now().Add(-time.Hour))
	if _, err := db.ExecContext(t.Context(), `
		UPDATE route_usage_outbox_items
		SET enqueued_at = (
			SELECT CASE sequence WHEN 1 THEN 2 ELSE 1 END
			FROM route_lifecycle_events
			WHERE id = route_usage_outbox_items.source_id
		)
		WHERE source_kind = 'lifecycle_event'
	`); err != nil {
		t.Fatal(err)
	}
	sequences := make(chan string, 2)
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		var batch routeusagev1.RouteLifecycleEventBatch
		if err := json.Unmarshal(body, &batch); err != nil || len(batch.Items) != 1 {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		sequences <- batch.Items[0].Sequence
		writeAcceptedBatchResponse(response, body)
	}))
	t.Cleanup(receiver.Close)
	sender, err := NewSender(store, receiver.URL, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if delivered, err := sender.SendOne(t.Context()); err != nil || !delivered {
			t.Fatalf("send lifecycle: delivered=%v err=%v", delivered, err)
		}
	}
	if first, second := <-sequences, <-sequences; first != "1" || second != "2" {
		t.Fatalf("lifecycle sequences = %q, %q", first, second)
	}
}

func TestLifecycleBatchSelectsOnlyEarliestEventPerRoute(t *testing.T) {
	db, store := newTestStore(t)
	otherRouteID := "route_other"
	insertLocalTestRoute(t, db, otherRouteID, "other.tnl.dev")
	enqueueRouteLifecycle(t, db, store, testRouteID, routes.LifecycleVersionStarted, time.Now())
	enqueueRouteLifecycle(t, db, store, testRouteID, routes.LifecycleReady, time.Now())
	enqueueRouteLifecycle(t, db, store, otherRouteID, routes.LifecycleVersionStarted, time.Now())

	rows, err := store.queries.ListRouteLifecycleOutboxBatch(t.Context(), maximumBatchItems)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("lifecycle batch size = %d, want 2", len(rows))
	}
	for _, row := range rows {
		if row.Sequence != 1 {
			t.Fatalf("route %q sequence = %d, want 1", row.RouteID, row.Sequence)
		}
	}
}

func TestSenderBatchesLifecycleEventsAcrossRoutesAndCorrelatesResultsByID(t *testing.T) {
	db, store := newTestStore(t)
	otherRouteID := "route_other"
	insertLocalTestRoute(t, db, otherRouteID, "other.tnl.dev")
	enqueueRouteLifecycle(t, db, store, testRouteID, routes.LifecycleVersionStarted, time.Now())
	enqueueRouteLifecycle(t, db, store, otherRouteID, routes.LifecycleVersionStarted, time.Now())

	received := make(chan routeusagev1.RouteLifecycleEventBatch, 1)
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var batch routeusagev1.RouteLifecycleEventBatch
		if err := json.NewDecoder(request.Body).Decode(&batch); err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		received <- batch
		code := routeusagev1.BatchProblemCodeStatusConflict
		results := []routeusagev1.BatchResult{
			{ItemId: batch.Items[1].ItemId, Accepted: false, Code: &code},
			{ItemId: batch.Items[0].ItemId, Accepted: true},
		}
		_ = json.NewEncoder(response).Encode(struct {
			Results []routeusagev1.BatchResult `json:"results"`
		}{Results: results})
	}))
	t.Cleanup(receiver.Close)
	sender, err := NewSender(store, receiver.URL, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	if delivered, err := sender.SendOne(t.Context()); !delivered || err == nil {
		t.Fatalf("mixed lifecycle batch: delivered=%v err=%v", delivered, err)
	}
	batch := <-received
	if len(batch.Items) != 2 || batch.Items[0].RouteId == batch.Items[1].RouteId {
		t.Fatalf("lifecycle batch = %+v", batch)
	}
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_usage_outbox_items"); count != 1 {
		t.Fatalf("remaining lifecycle outbox count = %d, want 1", count)
	}
	var remainingEventID string
	if err := db.QueryRowContext(t.Context(), `
		SELECT event.event_id
		FROM route_usage_outbox_items AS outbox
		JOIN route_lifecycle_events AS event ON event.id = outbox.source_id
	`).Scan(&remainingEventID); err != nil {
		t.Fatal(err)
	}
	if remainingEventID != batch.Items[1].ItemId {
		t.Fatalf("remaining event = %q, want %q", remainingEventID, batch.Items[1].ItemId)
	}
}

func TestSenderRejectsIncompleteBatchResponseWithoutAcknowledging(t *testing.T) {
	db, store := newTestStore(t)
	otherRouteID := "route_other"
	insertLocalTestRoute(t, db, otherRouteID, "other.tnl.dev")
	enqueueRouteLifecycle(t, db, store, testRouteID, routes.LifecycleVersionStarted, time.Now())
	enqueueRouteLifecycle(t, db, store, otherRouteID, routes.LifecycleVersionStarted, time.Now())
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var batch routeusagev1.RouteLifecycleEventBatch
		if err := json.NewDecoder(request.Body).Decode(&batch); err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(response).Encode(struct {
			Results []routeusagev1.BatchResult `json:"results"`
		}{Results: []routeusagev1.BatchResult{{ItemId: batch.Items[0].ItemId, Accepted: true}}})
	}))
	t.Cleanup(receiver.Close)
	sender, err := NewSender(store, receiver.URL, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	if delivered, err := sender.SendOne(t.Context()); !delivered || err == nil {
		t.Fatalf("incomplete response: delivered=%v err=%v", delivered, err)
	}
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_usage_outbox_items"); count != 2 {
		t.Fatalf("outbox count = %d, want 2", count)
	}
}

func TestSenderRejectsInvalidBatchResponses(t *testing.T) {
	const (
		firstID   = "event_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		secondID  = "event_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		unknownID = "event_cccccccccccccccccccccccccccccccc"
	)
	tests := map[string]struct {
		body    string
		message string
	}{
		"duplicate item": {
			body:    `{"results":[{"item_id":"` + firstID + `","accepted":true},{"item_id":"` + firstID + `","accepted":true}]}`,
			message: "duplicate item",
		},
		"unknown item": {
			body:    `{"results":[{"item_id":"` + firstID + `","accepted":true},{"item_id":"` + unknownID + `","accepted":true}]}`,
			message: "unknown item",
		},
		"malformed JSON": {body: `{"results":[`, message: "decode batch response"},
		"oversized body": {body: strings.Repeat(" ", maximumResponseBytes+1), message: "exceeds size limit"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(response, test.body)
			}))
			t.Cleanup(receiver.Close)
			sender, err := NewSender(nil, receiver.URL, "secret", nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := sender.postBatch(t.Context(), "/v1/routes/lifecycle-events", []byte(`{"items":[]}`), []string{firstID, secondID}); err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("batch response error = %v, want message containing %q", err, test.message)
			}
		})
	}
}

func TestSenderBatchesUsageReportsWithStableIDs(t *testing.T) {
	db, store := newTestStore(t)
	acknowledgeVersionStarted(t, db, store)
	start := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	for _, snapshot := range []UsageSnapshot{
		{RouteID: testRouteID, Version: 1, Resolution: "minute", BucketStart: start, Revision: 1, ObservedThrough: start.Add(time.Minute), Publish: true},
		{RouteID: testRouteID, Version: 1, Resolution: "hour", BucketStart: start, Revision: 1, ObservedThrough: start.Add(time.Minute), Publish: true},
	} {
		if err := store.SaveUsage(t.Context(), []UsageSnapshot{snapshot}); err != nil {
			t.Fatal(err)
		}
	}
	var initialIDs []string
	rows, err := db.QueryContext(t.Context(), "SELECT report_id FROM route_usage_reports ORDER BY report_id")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var reportID string
		if err := rows.Scan(&reportID); err != nil {
			t.Fatal(err)
		}
		initialIDs = append(initialIDs, reportID)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}

	received := make(chan routeusagev1.RouteUsageSnapshotBatch, 1)
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		var batch routeusagev1.RouteUsageSnapshotBatch
		if err := json.Unmarshal(body, &batch); err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		received <- batch
		writeAcceptedBatchResponse(response, body)
	}))
	t.Cleanup(receiver.Close)
	sender, err := NewSender(store, receiver.URL, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	if delivered, err := sender.SendOne(t.Context()); err != nil || !delivered {
		t.Fatalf("usage batch: delivered=%v err=%v", delivered, err)
	}
	batch := <-received
	if len(batch.Items) != 2 {
		t.Fatalf("usage batch size = %d, want 2", len(batch.Items))
	}
	wireIDs := []string{batch.Items[0].ItemId, batch.Items[1].ItemId}
	slices.Sort(wireIDs)
	if !slices.Equal(wireIDs, initialIDs) {
		t.Fatalf("usage report IDs = %v, want %v", wireIDs, initialIDs)
	}
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_usage_outbox_items"); count != 0 {
		t.Fatalf("outbox count = %d, want 0", count)
	}
}

func TestEncodeBatchHonorsRequestLimit(t *testing.T) {
	items := make([]string, maximumBatchItems)
	for index := range items {
		items[index] = strings.Repeat("x", maximumRequestBytes/maximumBatchItems)
	}
	count, body, err := encodeBatch(items)
	if err != nil {
		t.Fatal(err)
	}
	if count <= 0 || count >= maximumBatchItems || len(body) > maximumRequestBytes {
		t.Fatalf("encoded batch count=%d bytes=%d", count, len(body))
	}
	count, _, err = encodeBatch(make([]int, maximumBatchItems+1))
	if err != nil || count != maximumBatchItems {
		t.Fatalf("item-limited batch count=%d err=%v", count, err)
	}
}

func TestSenderIncludesExtendedUsageAndOmitsUndefinedHistograms(t *testing.T) {
	db, store := newTestStore(t)
	acknowledgeVersionStarted(t, db, store)
	start := time.Date(2026, time.September, 2, 12, 0, 0, 0, time.UTC)
	var openLatency durationHistogram
	if !openLatency.observe(25 * time.Millisecond) {
		t.Fatal("failed to observe test histogram")
	}
	visitors := new(visitorSketch)
	hash, ok := visitorNetworkHash(store.visitorMasterSecret, testRouteID, netip.MustParseAddr("192.0.2.1"), start)
	if !ok {
		t.Fatal("test visitor source was invalid")
	}
	visitors.insert(hash)
	if err := store.SaveUsage(t.Context(), []UsageSnapshot{{
		RouteID: testRouteID, Version: 1, Resolution: "minute", BucketStart: start,
		Revision: 1, ObservedThrough: start.Add(time.Minute), ConnectionAttempts: 5,
		PolicyDenials: 1, CapacityDenials: 2, PublisherOpenFailures: 1, SuccessfulStreams: 1,
		ConnectionNanoseconds: uint64(45 * time.Second), IngressBytes: 100, EgressBytes: 200,
		PublisherOpenLatency: openLatency.marshalBinary(), VisitorNetworkHLL: visitors.checkpoint(),
		VisitorNetworkEstimate: visitors.estimate(), Publish: true,
	}}); err != nil {
		t.Fatal(err)
	}
	received := make(chan routeusagev1.RouteUsageSnapshot, 1)
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		var batch routeusagev1.RouteUsageSnapshotBatch
		if err := json.Unmarshal(body, &batch); err != nil || len(batch.Items) != 1 {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		received <- batch.Items[0]
		writeAcceptedBatchResponse(response, body)
	}))
	t.Cleanup(receiver.Close)
	sender, err := NewSender(store, receiver.URL, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	if delivered, err := sender.SendOne(t.Context()); err != nil || !delivered {
		t.Fatalf("send usage: delivered=%v err=%v", delivered, err)
	}
	snapshot := <-received
	if snapshot.ConnectionAttempts != "5" || snapshot.PolicyDenials != "1" || snapshot.CapacityDenials != "2" ||
		snapshot.PublisherOpenFailures != "1" || snapshot.SuccessfulStreams != "1" ||
		snapshot.ConnectionNanoseconds != "45000000000" || snapshot.IngressBytes != "100" || snapshot.EgressBytes != "200" {
		t.Fatalf("usage payload counters = %+v", snapshot)
	}
	if snapshot.PublisherOpenLatency == nil || snapshot.PublisherOpenLatency.Count != "1" ||
		snapshot.PublisherOpenLatency.SumNanoseconds != "25000000" || len(snapshot.PublisherOpenLatency.CumulativeCounts) != 22 {
		t.Fatalf("usage payload publisher open latency = %+v", snapshot.PublisherOpenLatency)
	}
	if snapshot.TimeToFirstPublisherByte != nil || snapshot.SuccessfulConnectionDuration != nil {
		t.Fatalf("undefined usage histograms were sent: %+v", snapshot)
	}
	if snapshot.VisitorNetworkEstimate != "1" || !bytes.Equal(snapshot.VisitorNetworkHll, visitors.checkpoint()) {
		t.Fatalf("usage payload visitor sketch = estimate %s data %x", snapshot.VisitorNetworkEstimate, snapshot.VisitorNetworkHll)
	}
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_usage_snapshots"); count != 1 {
		t.Fatalf("incomplete usage count = %d, want 1", count)
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
		acceptRouteUsageRequest(response, request)
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
	if first, second := <-paths, <-paths; first != "/v1/routes/lifecycle-events" || second != "/v1/routes/usage-snapshots" {
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
	acknowledgeVersionStarted(t, db, store)
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
		body, err := io.ReadAll(request.Body)
		if err != nil {
			updateErrors <- err
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		var payload routeusagev1.RouteUsageSnapshotBatch
		if err := json.Unmarshal(body, &payload); err != nil || len(payload.Items) != 1 {
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
		writeAcceptedBatchResponse(response, body)
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

func TestSenderWakeDoesNotBypassFailureBackoff(t *testing.T) {
	db, store := newTestStore(t)
	enqueueLifecycle(t, db, store, time.Now())
	attempts := make(chan struct{}, 2)
	receiver := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		attempts <- struct{}{}
		response.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(receiver.Close)
	sender, err := NewSender(store, receiver.URL, "secret", nil)
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
	case <-attempts:
	case <-time.After(time.Second):
		t.Fatal("sender did not make its first attempt")
	}
	for range 100 {
		store.wakeSender()
	}
	select {
	case <-attempts:
		t.Fatal("sender wake bypassed failure backoff")
	case <-time.After(750 * time.Millisecond):
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
	if bucket.Finalized != 1 {
		t.Fatalf("recovered bucket finalized = %d, want 1", bucket.Finalized)
	}
	if count := scalar(t, db, "SELECT COUNT(*) FROM route_usage_outbox_items"); count != 1 {
		t.Fatalf("outbox count = %d, want 1", count)
	}
	recoveredAgain := NewCollector(store, nil)
	recoveredAgain.now = func() time.Time { return start.Add(3 * time.Minute) }
	if err := recoveredAgain.Recover(t.Context()); err != nil {
		t.Fatal(err)
	}
	if revision := scalar(t, db, "SELECT revision FROM route_usage_reports"); revision != 1 {
		t.Fatalf("recovered report revision = %d, want 1", revision)
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
	enqueueRouteLifecycle(t, db, store, testRouteID, routes.LifecycleVersionStarted, occurredAt)
}

func enqueueRouteLifecycle(
	t *testing.T,
	db *sql.DB,
	store *Store,
	routeID string,
	transition routes.LifecycleTransition,
	occurredAt time.Time,
) {
	t.Helper()
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := store.RecordLifecycle(t.Context(), statedb.New(db).WithTx(tx), routes.LifecycleChange{
		RouteID: routeID, Version: 1, OccurredAt: occurredAt, Transition: transition,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

const signedRouteInsertSQL = `
	INSERT INTO routes (
		id, hostname, local_target, status, version,
		authorization_issuer, authorization_id, authorization_key_id, authorization_retry_id,
		authorization_revision, authorization_expires_at, authorization_request_hash, created_at
	) VALUES (?, ?, 'localhost:8080', 'active', 1, 'https://authority.example', ?, ?, ?, 1, 2, zeroblob(32), 1)
`

func insertSignedTestRoute(t *testing.T, db *sql.DB, routeID, hostname, marker string) {
	t.Helper()
	if _, err := db.ExecContext(t.Context(), signedRouteInsertSQL,
		routeID, hostname, testAuthorizationID(marker), "key-"+marker, testRetryID(marker),
	); err != nil {
		t.Fatal(err)
	}
}

func insertLocalTestRoute(t *testing.T, db *sql.DB, routeID, hostname string) {
	t.Helper()
	hostnameID := "hostname_" + strings.TrimPrefix(routeID, "route_")
	if _, err := db.ExecContext(t.Context(), `
		INSERT INTO hostnames (id, identity_id, hostname, kind, status, source, created_at, activated_at)
		VALUES (?, 'identity_test', ?, 'managed', 'active', 'user', 1, 1)
	`, hostnameID, hostname); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(t.Context(), `
		INSERT INTO routes (id, hostname_id, identity_id, hostname, local_target, status, version, created_at)
		VALUES (?, ?, 'identity_test', ?, 'localhost:8080', 'active', 1, 1)
	`, routeID, hostnameID, hostname); err != nil {
		t.Fatal(err)
	}
}

func enqueueRegistration(t *testing.T, db *sql.DB, store *Store, routeID, hostname, marker string) {
	t.Helper()
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := store.RecordRegistration(
		t.Context(), statedb.New(db).WithTx(tx), testRegistration(routeID, hostname, marker),
	); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func testRegistration(routeID, hostname, marker string) routes.RouteRegistration {
	return routes.RouteRegistration{
		RegistrationID:  "registration_" + strings.Repeat(marker, 32),
		RouteID:         routeID,
		Hostname:        hostname,
		SigningKeyID:    "key-" + marker,
		AuthorizationID: testAuthorizationID(marker),
		CreatedAt:       time.Unix(0, 1).UTC(),
		RetryID:         testRetryID(marker),
	}
}

func testAuthorizationID(marker string) string {
	return "authorization_" + strings.Repeat(marker, 32)
}

func testRetryID(marker string) string {
	return "retry_" + strings.Repeat(marker, 32)
}

func loadUsageBucket(t *testing.T, queries *statedb.Queries, resolution string, start time.Time) statedb.RouteUsageSnapshot {
	return loadUsageBucketVersion(t, queries, 1, resolution, start)
}

func loadUsageBucketVersion(
	t *testing.T,
	queries *statedb.Queries,
	version uint64,
	resolution string,
	start time.Time,
) statedb.RouteUsageSnapshot {
	t.Helper()
	bucket, err := queries.GetRouteUsageSnapshot(t.Context(), statedb.GetRouteUsageSnapshotParams{
		RouteID: testRouteID, Version: int64(version), Resolution: resolution, BucketStart: start.UnixNano(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return bucket
}

func decodeTestHistogram(t *testing.T, data []byte) durationHistogram {
	t.Helper()
	histogram, err := unmarshalDurationHistogram(data)
	if err != nil {
		t.Fatal(err)
	}
	return histogram
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
	if bucket.ConnectionAttempts != connections ||
		bucket.ConnectionNanoseconds != int64(duration) ||
		bucket.IngressBytes != ingress ||
		bucket.EgressBytes != egress ||
		bucket.Complete != complete ||
		bucket.Revision != revision {
		t.Fatalf("usage bucket = %+v", bucket)
	}
}

func acknowledgeVersionStarted(t *testing.T, db *sql.DB, store *Store) {
	t.Helper()
	enqueueLifecycle(t, db, store, time.Now())
	if _, err := db.ExecContext(t.Context(), `
		DELETE FROM route_usage_outbox_items
		WHERE source_kind = 'lifecycle_event'
	`); err != nil {
		t.Fatal(err)
	}
}

func acceptRouteUsageRequest(response http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/v1/routes" {
		response.WriteHeader(http.StatusNoContent)
		return
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	writeAcceptedBatchResponse(response, body)
}

func writeAcceptedBatchResponse(response http.ResponseWriter, body []byte) {
	var envelope struct {
		Items []struct {
			ItemID string `json:"item_id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	results := make([]routeusagev1.BatchResult, len(envelope.Items))
	for index, item := range envelope.Items {
		results[index] = routeusagev1.BatchResult{ItemId: item.ItemID, Accepted: true}
	}
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(struct {
		Results []routeusagev1.BatchResult `json:"results"`
	}{Results: results})
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
