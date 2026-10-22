package controlstate

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

// a publisher can disappear without closing its publish run. its expired
// reservations must not exhaust placement for unrelated public URLs.
func TestIntegrationExpiredPublishRunReleasesPlacementForOtherPublicURL(t *testing.T) {
	database, now, first, _ := newPublishRunPrerequisites(t)
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.relay_leases SET connection_capacity = 1`); err != nil {
		t.Fatal(err)
	}
	seedControlPublicURL(t, database, now, "other")
	second := first
	second.PublicURLID = "public_url_other"
	second.TeamID = "team_other"
	second.ActingIdentityID = "identity_other"
	second.MembershipID = "membership_other"
	second.IdempotencyKey = "other"
	second.RequestDigest = sha256.Sum256([]byte("other"))
	second.CertificateIdentifiers = []string{"route-other.example.test"}
	second.CertificateCacheKey = "certificate_other"

	setup, err := database.CreatePublishRun(t.Context(), first, now, 30*time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	assertAssignmentTotals(t, database.pool, 2)
	if _, err := database.CreatePublishRun(t.Context(), second, now.Add(time.Second), 30*time.Second, time.Minute); !errors.Is(err, ErrInsufficientRelayServices) {
		t.Fatalf("live publish run must hold both placement slots: %v", err)
	}

	// no publisher retry or mutation of the first public URL occurs after expiry.
	later := now.Add(31 * time.Second)
	if _, err := database.CreatePublishRun(t.Context(), second, later, 30*time.Second, time.Minute); err != nil {
		t.Fatalf("expired publish run %s still holds unrelated relay capacity: %v", setup.PublishRunID, err)
	}
	assertAssignmentTotals(t, database.pool, 2)
	var expired bool
	if err := database.pool.QueryRow(t.Context(), `SELECT state = 'expired' AND close_reason = 'publisher_expired' AND closed_at = publisher_expires_at
		FROM control.publish_runs WHERE id = $1`, setup.PublishRunID).Scan(&expired); err != nil || !expired {
		t.Fatalf("old publish run expired = %t, %v", expired, err)
	}
}

func TestIntegrationExpireSavedPublishRunsPublishesTombstones(t *testing.T) {
	f := newPublishRunFixture(t)
	readyTestSession(t, f)
	assertAssignmentTotals(t, f.database.pool, 2)

	// cleanup works without an API request for this public URL, as when a
	// control starts after an idle publisher has disappeared.
	count, err := f.database.ExpireSavedPublishRuns(t.Context(), f.now.Add(31*time.Second))
	if err != nil || count != 1 {
		t.Fatalf("cleanup = %d, %v", count, err)
	}
	assertAssignmentTotals(t, f.database.pool, 0)
	var expired, connectionsClosed bool
	if err := f.database.pool.QueryRow(t.Context(), `SELECT state = 'expired' AND closed_at = publisher_expires_at,
		(SELECT count(*) = 2 FROM control.publish_run_connection_slots WHERE publish_run_id = $1 AND state = 'closed')
		FROM control.publish_runs WHERE id = $1`, f.setup.PublishRunID).Scan(&expired, &connectionsClosed); err != nil || !expired || !connectionsClosed {
		t.Fatalf("expired run/connections = %t/%t: %v", expired, connectionsClosed, err)
	}
	var eventKind string
	if err := f.database.pool.QueryRow(t.Context(), `SELECT event_kind FROM control.ingress_routing_table_events
		WHERE public_url_id = $1 ORDER BY id DESC LIMIT 1`, f.setup.PublicURLID).Scan(&eventKind); err != nil || eventKind != string(IngressPublicURLTombstone) {
		t.Fatalf("latest routing event = %q, %v", eventKind, err)
	}
	if count, err := f.database.ExpireSavedPublishRuns(t.Context(), f.now.Add(time.Minute)); err != nil || count != 0 {
		t.Fatalf("repeated cleanup = %d, %v", count, err)
	}
}

func TestIntegrationExpireSavedPublishRunsSkipsLockedPublicURL(t *testing.T) {
	f := newPublishRunFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	gate, err := f.database.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(ctx, `SELECT id FROM control.public_urls WHERE id = $1 FOR NO KEY UPDATE`, f.setup.PublicURLID); err != nil {
		t.Fatal(err)
	}
	if count, err := f.database.ExpireSavedPublishRuns(ctx, f.now.Add(31*time.Second)); err != nil || count != 0 {
		t.Fatalf("locked public URL cleanup = %d, %v", count, err)
	}
	if err := gate.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if count, err := f.database.ExpireSavedPublishRuns(ctx, f.now.Add(31*time.Second)); err != nil || count != 1 {
		t.Fatalf("unlocked public URL cleanup = %d, %v", count, err)
	}
}
