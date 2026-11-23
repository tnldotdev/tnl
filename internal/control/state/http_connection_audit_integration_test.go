package state

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
)

func TestIntegrationPublisherAuditReadsGrantAfterRunWait(t *testing.T) {
	f := newServicePublicationFixture(t)
	db, run, now := f.database, f.run, f.now
	installPrivateTestCertificate(t, db, f.prepared, run, now)
	f.readyConnections(t, now)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := db.HeartbeatServiceRun(ctx, run.ServiceID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal(err)
	}
	gate, err := db.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(ctx, "SELECT id FROM control.service_runs WHERE id=$1 FOR UPDATE", run.RunID); err != nil {
		t.Fatal(err)
	}
	// both requests arrive before the grant changes. cancel the first while
	// it is blocked on the run; the second must read the committed cutoff.
	event := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: run.ServiceID, ServiceKind: "service", RunID: run.RunID, RunNumber: run.RunNumber, VisitorConnectionID: mustOpaqueID(t, opaqueid.VisitorConnectionPrefix), SourceIP: "192.0.2.10", EventType: "http.decision", Outcome: "allowed", OccurredAt: now.Add(2 * time.Second)}
	send := func(ctx context.Context, e serviceaudit.Observation) error {
		_, err := db.IngestServiceRunObservations(ctx, run.ServiceID, run.RunID, run.Token, run.RunNumber, serviceaudit.Batch{Events: []serviceaudit.Observation{e}}, e.OccurredAt)
		return err
	}
	pid := int32(gate.Conn().PgConn().PID())
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	done := make(chan error, 1)
	one, stop := context.WithCancel(ctx)
	defer stop()
	workers.Go(func() { done <- send(one, event) })
	waitForPostgresBlock(t, ctx, db, pid, done)
	stop()
	if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled report: %v", err)
	}
	next := event
	next.EventID = serviceaudit.NewID()
	workers.Go(func() { done <- send(ctx, next) })
	waitForPostgresBlock(t, ctx, db, pid, done)
	if _, err := gate.Exec(ctx, "UPDATE control.publisher_grants SET revoked_at=$2 WHERE id=$1", f.publisher.GrantID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrServiceAuditAccess) {
		t.Fatalf("report did not observe revocation: %v", err)
	}
	var count int
	if err := db.pool.QueryRow(ctx, "SELECT count(*) FROM control.service_audit_events WHERE id=ANY($1)", []string{event.EventID, next.EventID}).Scan(&count); err != nil || count != 0 {
		t.Fatalf("stored canceled or denied events: %d, %v", count, err)
	}
}

func TestIntegrationHTTPConnectionAuditUsesExactPublisherRunAndOriginalDeadline(t *testing.T) {
	f := newServicePublicationFixture(t)
	d, now, service, run := f.database, f.now, f.service, f.run
	installPrivateTestCertificate(t, d, f.prepared, run, now)
	f.readyConnections(t, now)
	if _, err := d.HeartbeatServiceRun(t.Context(), service.ID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal(err)
	}
	opened := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: service.ID, ServiceKind: "service",
		RunID: run.RunID, RunNumber: run.RunNumber, VisitorConnectionID: mustOpaqueID(t, opaqueid.VisitorConnectionPrefix),
		SourceIP: "192.0.2.10", EventType: "connection.open", Outcome: "allowed", OccurredAt: now}
	if err := d.RevokePublisherGrant(t.Context(), service.TeamID, f.publisher.ID, f.publisher.GrantID, f.actor(t), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	closed := opened
	closed.EventID, closed.EventType, closed.Outcome, closed.Reason = serviceaudit.NewID(), "connection.close", "closed", "closed"
	closed.OccurredAt = now.Add(2 * time.Second)
	batch := serviceaudit.Batch{Events: []serviceaudit.Observation{opened, closed, opened}}
	if result, err := d.IngestServiceRunObservations(t.Context(), service.ID, run.RunID, run.Token, run.RunNumber, batch, now.Add(30*time.Second)); err != nil || result.Accepted != 2 || result.Duplicates != 1 {
		t.Fatal("delayed HTTP connection history did not commit exactly once", result, err)
	}
	page, err := d.ListServiceAudit(t.Context(), service.TeamID, f.actor(t), ServiceAuditFilter{ServiceID: service.ID}, now.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, event := range page.Events {
		if event.ID != opened.EventID && event.ID != closed.EventID {
			continue
		}
		found++
		if event.PublisherIdentityID != f.publisher.ID || event.ActorIdentityID != "" || event.DeviceID != "" ||
			event.RunID != run.RunID || event.SourceIP != "" || event.SourceDigest != auditSourceDigest(t, d, service.ID, opened.SourceIP) {
			t.Fatal("HTTP connection history invented an actor or lost its publisher/source", event)
		}
	}
	if found != 2 {
		t.Fatal("HTTP connection history is missing", found)
	}
	// a committed conflicting ID must roll back its fresh neighbor too, after
	// authorization has accepted every event and the bulk insert has run.
	neighbor, conflict := opened, opened
	neighbor.EventID = serviceaudit.NewID()
	conflict.SourceIP = "192.0.2.11"
	result, err := d.IngestServiceRunObservations(t.Context(), service.ID, run.RunID, run.Token, run.RunNumber,
		serviceaudit.Batch{Events: []serviceaudit.Observation{neighbor, conflict}}, now.Add(30*time.Second))
	if !errors.Is(err, ErrServiceAuditAccess) || result != (ServiceObservationResult{}) {
		t.Fatal("conflicting retry acknowledged a partially accepted batch", result, err)
	}
	var retained int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_audit_events WHERE id=$1`, neighbor.EventID).Scan(&retained); err != nil || retained != 0 {
		t.Fatal("conflicting retry committed its fresh neighbor", retained, err)
	}
	for _, test := range []struct {
		name   string
		change func(*serviceaudit.Observation)
	}{
		{"post-revocation open", func(o *serviceaudit.Observation) { o.OccurredAt = now.Add(2 * time.Second) }},
		{"request deadline", func(o *serviceaudit.Observation) {
			o.EventType, o.Outcome, o.OccurredAt = "http.decision", "denied", now.Add(2*time.Second)
		}},
		{"late cleanup", func(o *serviceaudit.Observation) {
			o.EventType, o.Outcome, o.OccurredAt = "connection.close", "closed", now.Add(serviceObservationDeliveryGrace+2*time.Second)
		}},
		{"service", func(o *serviceaudit.Observation) { o.ServiceID = mustOpaqueID(t, opaqueid.ServicePrefix) }},
		{"run", func(o *serviceaudit.Observation) { o.RunID = mustOpaqueID(t, opaqueid.ServiceRunPrefix) }},
		{"number", func(o *serviceaudit.Observation) { o.RunNumber++ }},
		{"connector pair", func(o *serviceaudit.Observation) { o.PairID, o.DeliveryGeneration = mustOpaqueID(t, "cpp_"), 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			event := opened
			event.EventID = serviceaudit.NewID()
			test.change(&event)
			observed := now.Add(30 * time.Second)
			if event.OccurredAt.After(observed) {
				observed = event.OccurredAt
			}
			_, err := d.IngestServiceRunObservations(t.Context(), service.ID, run.RunID, run.Token, run.RunNumber,
				serviceaudit.Batch{Events: []serviceaudit.Observation{event}}, observed)
			if !errors.Is(err, ErrServiceAuditAccess) && !(test.name == "late cleanup" && errors.Is(err, ErrServiceAccess)) {
				t.Fatal("HTTP connection history escaped its exact run or original deadline", err)
			}
		})
	}
}
