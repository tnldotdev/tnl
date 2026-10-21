package controlstate

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIntegrationSharedPrivateSlotLifecycleReview(t *testing.T) {
	runs, _, _, creation := poolReviewFixtures(t)
	d, now := runs[0].database, runs[0].now
	service, err := d.CreatePrivateService(t.Context(), creation.TeamID, creation.ActingIdentityID, "database", "database", now)
	if err != nil {
		t.Fatal(err)
	}
	enrollment := publisherEnrollment(t, d, creation, PublisherScope{TeamID: creation.TeamID, Kind: "private_service", PrivateServiceID: service.ID}, now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := d.PreparePrivateServiceRun(t.Context(), service.ID, publisher, "private", now)
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartManagedServiceRun(t.Context(), service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, slot := range run.Connections {
		lease := runs[0].leases[slot.RelayServiceID].RelayLeaseIdentity
		if _, err = d.ClaimPrivatePublisherConnection(t.Context(), slot.PublisherConnectionID, service.ID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, lease, now); err != nil {
			t.Fatal(err)
		}
		if _, err = d.ReadyPrivatePublisherConnection(t.Context(), slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
			t.Fatal(err)
		}
	}
	var ready, foreign int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.publisher_service_connection_slots WHERE run_id=$1 AND service_kind='private' AND state='ready' AND session_open AND private_parent_id=run_id AND public_parent_id IS NULL`, run.RunID).Scan(&ready); err != nil || ready != 2 {
		t.Fatalf("private ready slots are not canonical rows: %d %v", ready, err)
	}
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.publish_run_connection_slots WHERE publish_run_id=$1`, run.RunID).Scan(&foreign); err != nil || foreign != 0 {
		t.Fatal("HTTP slot view crossed the private boundary", err)
	}
	_, err = d.pool.Exec(t.Context(), `UPDATE control.private_service_connection_slots SET publisher_connection_id=$2 WHERE private_run_id=$1 AND connection_slot=0`, run.RunID, runs[0].setup.PublisherConnections[0].PublisherConnectionID)
	var violation *pgconn.PgError
	if !errors.As(err, &violation) || violation.Code != "23505" {
		t.Fatalf("private slot reused an HTTP connection ID: %v", err)
	}
	if err = d.ClosePrivateServiceRun(t.Context(), service.ID, run.RunID, run.Token, now); err != nil {
		t.Fatal(err)
	}
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.publisher_service_connection_slots WHERE session_open AND state='ready'`).Scan(&ready); err != nil || ready != 4 {
		t.Fatalf("private parent cascade disturbed live HTTP pools: %d %v", ready, err)
	}
}
