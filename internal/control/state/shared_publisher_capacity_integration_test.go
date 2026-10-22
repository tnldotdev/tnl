package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func TestIntegrationPublicAndPrivatePublishersShareRelayPlacementCapacity(t *testing.T) {
	d, now, request, _ := newPublishRunPrerequisites(t)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.relay_leases SET connection_capacity=1`); err != nil {
		t.Fatal(err)
	}
	publicRun, err := d.CreatePublishRun(t.Context(), request, now, time.Minute, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	privateRequest := oidcRouteRequest(t, d, now)
	service, err := d.CreateServiceAt(t.Context(), privateRequest.TeamID, privateRequest.ActingIdentityID, "private", "private", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	enrollment := publisherEnrollment(t, d, privateRequest, PublisherScope{TeamID: privateRequest.TeamID, Kind: "service", ServiceID: service.ID}, now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := d.PrepareServiceRun(t.Context(), service.ID, publisher, "private", now, ServiceMetadata{Protocol: "tcp", TrustRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.StartServiceRun(t.Context(), service.ID, prepared.RunID, prepared.RunNumber, publisher, now); !errors.Is(err, ErrInsufficientRelayServices) {
		t.Fatalf("private run bypassed HTTP relay reservations: %v", err)
	}
	if err = d.ClosePublishRun(t.Context(), publicRun.PublishRunID, publicRun.PublishRunToken, now); err != nil {
		t.Fatal(err)
	}
	serviceRun, err := d.StartServiceRun(t.Context(), service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil || len(serviceRun.Connections) != 2 {
		t.Fatalf("released HTTP capacity could not serve private run: %+v %v", serviceRun, err)
	}
	var slots int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.publisher_service_connection_slots WHERE session_open AND state='assigned'`).Scan(&slots); err != nil || slots != 2 {
		t.Fatalf("shared live slots=%d: %v", slots, err)
	}
	if expired, err := d.ExpireSavedPublishRuns(t.Context(), now.Add(time.Minute)); err != nil || expired != 1 {
		t.Fatalf("shared worker did not expire private run: %d %v", expired, err)
	}
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.publisher_service_connection_slots WHERE session_open`).Scan(&slots); err != nil || slots != 0 {
		t.Fatalf("expired private run held relay capacity: %d %v", slots, err)
	}
}
