package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationPublicAndPrivatePublishersShareRelayPlacementCapacity(t *testing.T) {
	f := newServicePublicationFixture(t)
	d, now := f.database, f.now
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.relay_leases SET connection_capacity=1`); err != nil {
		t.Fatal(err)
	}
	if err := d.CloseServiceRun(t.Context(), f.service.ID, f.run.RunID, f.run.Token, now); err != nil {
		t.Fatal(err)
	}
	f.start(t, "public", now)
	publicRun := f.run

	editorID := f.actor(t)
	private, err := d.CreateServiceAt(t.Context(), f.service.TeamID, editorID, "private", "private", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := controlstatedb.New(d.pool).GetTeamActorContext(t.Context(), controlstatedb.GetTeamActorContextParams{TeamID: f.service.TeamID, IdentityID: editorID})
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := d.IssuePublisherEnrollment(t.Context(), CreatePublisherEnrollmentRequest{
		Scope: PublisherScope{TeamID: f.service.TeamID, Kind: "service", ServiceID: private.ID},
		Name:  "private", Kind: "installed", EditorID: editorID, EditorMembershipID: actor.ActorMembershipID,
		PolicyRevision: uint64(actor.PolicyRevision), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := d.PrepareServiceRun(t.Context(), private.ID, publisher, "private", now, ServiceRunRequest{Metadata: ServiceMetadata{Protocol: "tcp", TrustRevision: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.StartServiceRun(t.Context(), private.ID, prepared.RunID, prepared.RunNumber, publisher, now); !errors.Is(err, ErrInsufficientRelayServices) {
		t.Fatalf("private run bypassed HTTP relay reservations: %v", err)
	}
	if err = d.CloseServiceRun(t.Context(), f.service.ID, publicRun.RunID, publicRun.Token, now); err != nil {
		t.Fatal(err)
	}
	serviceRun, err := d.StartServiceRun(t.Context(), private.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil || len(serviceRun.Connections) != 2 {
		t.Fatalf("released HTTP capacity could not serve private run: %+v %v", serviceRun, err)
	}
	// keep the original one-minute cleanup boundary, independently of the
	// shorter publisher liveness deadline returned by start.
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.service_runs SET serving_until=$2 WHERE id=$1`,
		serviceRun.RunID, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if expired, err := d.ExpireServiceRuns(t.Context(), serviceRun.ExpiresAt); err != nil || expired != 0 {
		t.Fatal("publisher liveness expiry released private serving capacity", expired, err)
	}
	var slots int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_connection_slots WHERE session_open AND state='assigned'`).Scan(&slots); err != nil || slots != 2 {
		t.Fatalf("shared live slots=%d: %v", slots, err)
	}
	if expired, err := d.ExpireServiceRuns(t.Context(), now.Add(time.Minute)); err != nil || expired != 1 {
		t.Fatalf("shared worker did not expire private run: %d %v", expired, err)
	}
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_connection_slots WHERE session_open`).Scan(&slots); err != nil || slots != 0 {
		t.Fatalf("expired private run held relay capacity: %d %v", slots, err)
	}
}
