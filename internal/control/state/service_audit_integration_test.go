package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
)

func TestIntegrationServiceAuditTransactionalManagement(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	creation := oidcRouteRequest(t, d, now)
	service, err := d.CreateServiceAt(t.Context(), creation.TeamID, creation.ActingIdentityID, "audit-db", "audit-db", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	retry, err := d.CreateServiceAt(t.Context(), creation.TeamID, creation.ActingIdentityID, "audit-db", "audit-db", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"})
	if err != nil || retry.ID != service.ID {
		t.Fatal("unstable retry", err)
	}
	page, err := d.ListServiceAudit(t.Context(), creation.TeamID, creation.ActingIdentityID, ServiceAuditFilter{ServiceID: service.ID, Limit: 1}, now)
	if err != nil || len(page.Events) != 1 || page.NextCursor == "" || page.Events[0].EventType != "service.create" {
		t.Fatalf("first page %+v %v", page, err)
	}
	next, err := d.ListServiceAudit(t.Context(), creation.TeamID, creation.ActingIdentityID, ServiceAuditFilter{ServiceID: service.ID, After: page.NextCursor}, now)
	if err != nil || len(next.Events) != 1 || next.Events[0].EventType != "grant.create" {
		t.Fatalf("idempotent event page %+v %v", next, err)
	}
	if _, err = d.pool.Exec(t.Context(), `ALTER TABLE control.service_audit_events ADD CONSTRAINT reject_audit_grant CHECK(event_type<>'grant.create') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	_, err = d.CreateServiceGrant(t.Context(), service.ID, creation.ActingIdentityID, "rollback", "team", "", nil, now)
	if err == nil {
		t.Fatal("mutation committed without audit")
	}
	var count int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.visitor_grants WHERE service_id=$1 AND kind='team'`, service.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("grant escaped rollback: %d %v", count, err)
	}
	if _, err = d.pool.Exec(t.Context(), `ALTER TABLE control.service_audit_events DROP CONSTRAINT reject_audit_grant`); err != nil {
		t.Fatal(err)
	}
	// a helper failure rolls back together with other caller changes.
	insertAuthorityIdentity(t, d, "identity_audit_foreign", "", false, now)
	tx, err := d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	e := serviceaudit.Event{TeamID: creation.TeamID, ServiceID: service.ID, ServiceKind: "service", EventType: "apply", OccurredAt: now, ActorIdentityID: "wrong-team:secret"}
	if err = RecordServiceAudit(t.Context(), tx, e, "apply-request"); !errors.Is(err, serviceaudit.ErrInvalid) {
		t.Fatalf("malformed actor: %v", err)
	}
	e.ActorIdentityID = "identity_audit_foreign"
	if err = RecordServiceAudit(t.Context(), tx, e, "apply-request"); !errors.Is(err, ErrServiceAuditAccess) {
		t.Fatalf("actor outside the team: %v", err)
	}
	e.ActorIdentityID = creation.ActingIdentityID
	if err = RecordServiceAudit(t.Context(), tx, e, "apply-request"); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_audit_events WHERE event_type='apply'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("audit escaped rollback", err)
	}
	other, _ := opaqueid.New(opaqueid.IdentityPrefix)
	if _, err = d.ListServiceAudit(t.Context(), creation.TeamID, other, ServiceAuditFilter{}, now); !errors.Is(err, ErrServiceAuditAccess) {
		t.Fatalf("other identity read audit: %v", err)
	}
	foreign, _ := opaqueid.New(opaqueid.TeamPrefix)
	if _, err = d.ListServiceAudit(t.Context(), foreign, creation.ActingIdentityID, ServiceAuditFilter{}, now); !errors.Is(err, ErrServiceAuditAccess) {
		t.Fatalf("other team read audit: %v", err)
	}
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.service_audit_events SET received_at=$1 WHERE service_id=$2`, now.Add(-serviceaudit.Retention-time.Second), service.ID); err != nil {
		t.Fatal(err)
	}
	if page, err = d.ListServiceAudit(t.Context(), creation.TeamID, creation.ActingIdentityID, ServiceAuditFilter{ServiceID: service.ID}, now); err != nil || len(page.Events) != 0 {
		t.Fatal("retention read exposed expired events", err)
	}
	if n, err := d.CleanupServiceAudit(t.Context(), now, 1); err != nil || n != 1 {
		t.Fatalf("unbounded cleanup %d %v", n, err)
	}
}

func TestIntegrationServiceAuditAuthenticatedBatches(t *testing.T) {
	runs, _, _, creation := poolReviewFixtures(t)
	f := runs[0]
	d, now := f.database, f.now
	visitor, _ := opaqueid.New(opaqueid.VisitorConnectionPrefix)
	o := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: f.setup.PublicURLID, ServiceKind: "public_url", RunID: f.setup.PublishRunID, RunNumber: int64(f.setup.PublishRunNumber), VisitorConnectionID: visitor, SourceIP: "192.0.2.3", OccurredAt: now, EventType: "http.decision", Outcome: "denied", Reason: "authorization"}
	batch := serviceaudit.Batch{Events: []serviceaudit.Observation{o, o}}
	result, err := d.IngestPublisherServiceObservations(t.Context(), f.authentication(), batch, now)
	if err != nil || result.Accepted != 1 || result.Duplicates != 1 {
		t.Fatalf("dedup result %+v %v", result, err)
	}
	if _, err = d.IngestPublisherServiceObservations(t.Context(), runs[1].authentication(), batch, now); !errors.Is(err, ErrServiceAuditAccess) {
		t.Fatalf("cross-run audit accepted: %v", err)
	}
	bad := f.authentication()
	bad.PublishRunToken = runs[1].setup.PublishRunToken
	if _, err = d.IngestPublisherServiceObservations(t.Context(), bad, batch, now); !errors.Is(err, ErrPublishRunCredential) {
		t.Fatalf("cross-run token accepted: %v", err)
	}
	lease := registerTestIngress(t, d, now)
	o.EventID = serviceaudit.NewID()
	o.EventType = "connection.open"
	o.Outcome = "forwarded"
	o.Reason = ""
	batch.Events = []serviceaudit.Observation{o}
	if result, err = d.IngestIngressServiceObservations(t.Context(), lease.IngressLeaseIdentity, batch, now); err != nil || result.Accepted != 1 {
		t.Fatalf("ingress observation %+v %v", result, err)
	}
	serviceDenial := o
	serviceDenial.EventID = serviceaudit.NewID()
	serviceDenial.RunID = ""
	serviceDenial.RunNumber = 0
	serviceDenial.Outcome = "denied"
	serviceDenial.Reason = "capacity"
	if result, err = d.IngestIngressServiceObservations(t.Context(), lease.IngressLeaseIdentity, serviceaudit.Batch{Events: []serviceaudit.Observation{serviceDenial}}, now); err != nil || result.Accepted != 1 {
		t.Fatalf("known service denial before run selection: %+v %v", result, err)
	}
	stale := lease.IngressLeaseIdentity
	stale.IngressLeaseRevision++
	if _, err = d.IngestIngressServiceObservations(t.Context(), stale, batch, now); !errors.Is(err, ErrIngressLeaseStale) {
		t.Fatalf("stale ingress accepted: %v", err)
	}
	o.EventID = serviceaudit.NewID()
	o.RunID = runs[1].setup.PublishRunID
	o.RunNumber = int64(runs[1].setup.PublishRunNumber) + 1
	batch.Events = append(batch.Events, o)
	if _, err = d.IngestIngressServiceObservations(t.Context(), lease.IngressLeaseIdentity, batch, now); !errors.Is(err, ErrServiceAuditAccess) {
		t.Fatalf("mixed invalid batch accepted: %v", err)
	}
	page, err := d.ListServiceAudit(t.Context(), creation.TeamID, creation.ActingIdentityID, ServiceAuditFilter{ServiceID: f.setup.PublicURLID}, now)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range page.Events {
		if seen[e.ID] {
			t.Fatal("duplicate durable event")
		}
		seen[e.ID] = true
		if _, err = strconv.ParseInt(e.Cursor, 10, 64); err != nil {
			t.Fatal(err)
		}
	}
	if !seen[batch.Events[0].EventID] {
		t.Fatal("missing committed observation")
	}
}

func TestIntegrationServiceAuditPrivateSourceScope(t *testing.T) {
	runs, _, _, creation := poolReviewFixtures(t)
	d, now := runs[0].database, runs[0].now
	service, err := d.CreateServiceAt(t.Context(), creation.TeamID, creation.ActingIdentityID, "audit-private", "audit-private", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	enrollment := publisherEnrollment(t, d, creation, PublisherScope{TeamID: creation.TeamID, Kind: "service", ServiceID: service.ID}, now)
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.PrepareServiceRun(t.Context(), service.ID, publisher, "audit-private", now, ServiceMetadata{Protocol: "tcp", TrustRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	public, _, _ = ed25519.GenerateKey(rand.Reader)
	device, err := d.EnrollVisitorDevice(t.Context(), creation.ActingIdentityID, public, now)
	if err != nil {
		t.Fatal(err)
	}
	lease := registerTestIngress(t, d, now)
	visitor, _ := opaqueid.New(opaqueid.VisitorConnectionPrefix)
	// seed the already-authenticated admission facts; the transport suite owns
	// device proof and stream handshake. audit must independently check this scope.
	_, err = d.pool.Exec(t.Context(), `INSERT INTO control.direct_service_visitors(visitor_connection_id,service_id,service_run_id,run_number,identity_id,device_id,certificate_digest,source_ip,ingress_id,ingress_run_id,ingress_lease_revision,destination_port,valid_until,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$12,'192.0.2.9',$7,$8,$9,25443,$10,$11)`, visitor, service.ID, run.RunID, run.RunNumber, creation.ActingIdentityID, device.ID, lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision), now.Add(time.Minute), now, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	o := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: service.ID, ServiceKind: "service", RunID: run.RunID, RunNumber: run.RunNumber, VisitorConnectionID: visitor, SourceIP: "192.0.2.9", EventType: "connection.open", Outcome: "allowed", OccurredAt: now}
	batch := serviceaudit.Batch{Events: []serviceaudit.Observation{o}}
	if result, err := d.IngestIngressServiceObservations(t.Context(), lease.IngressLeaseIdentity, batch, now); err != nil || result.Accepted != 1 {
		t.Fatalf("valid private scope: %+v %v", result, err)
	}
	o.EventID = serviceaudit.NewID()
	o.SourceIP = "192.0.2.10"
	batch.Events = []serviceaudit.Observation{o}
	if _, err = d.IngestIngressServiceObservations(t.Context(), lease.IngressLeaseIdentity, batch, now); !errors.Is(err, ErrServiceAuditAccess) {
		t.Fatalf("manufactured source accepted: %v", err)
	}
	other, err := d.RegisterIngress(t.Context(), IngressRegistration{IngressID: "other-ingress", IngressRunID: "other-run", ProtocolVersion: 1, ConnectionCapacity: 10}, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	o.SourceIP = "192.0.2.9"
	batch.Events = []serviceaudit.Observation{o}
	if _, err = d.IngestIngressServiceObservations(t.Context(), other.IngressLeaseIdentity, batch, now); !errors.Is(err, ErrServiceAuditAccess) {
		t.Fatalf("another ingress manufactured private visitor: %v", err)
	}
	// a direct denial still needs the exact pending reservation and run.
	o.EventID = serviceaudit.NewID()
	o.Outcome = "denied"
	o.Reason = "authorization"
	batch.Events = []serviceaudit.Observation{o}
	if _, err = d.IngestIngressServiceObservations(t.Context(), lease.IngressLeaseIdentity, batch, now); err != nil {
		t.Fatal("lost pre-admission denial", err)
	}
	page, err := d.ListServiceAudit(t.Context(), creation.TeamID, creation.ActingIdentityID, ServiceAuditFilter{ServiceID: service.ID}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range page.Events {
		if e.EventType == "connection.open" && (e.ActorIdentityID != creation.ActingIdentityID || e.DeviceID != device.ID) {
			t.Fatalf("identity not derived from authenticated scope: %+v", e)
		}
		if e.ID == o.EventID && (e.RunID != run.RunID || e.PublisherIdentityID != publisher.ID) {
			t.Fatalf("direct denial lost the selected run or publisher: %+v", e)
		}
	}
	// an unrelated visitor cannot borrow a real run or its identity.
	o.EventID = serviceaudit.NewID()
	o.VisitorConnectionID = mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
	if _, err = d.IngestIngressServiceObservations(t.Context(), lease.IngressLeaseIdentity, serviceaudit.Batch{Events: []serviceaudit.Observation{o}}, now); !errors.Is(err, ErrServiceAuditAccess) {
		t.Fatalf("session denial asserted an unadmitted run: %v", err)
	}
	o.VisitorConnectionID = visitor
	for _, change := range []func(*serviceaudit.Observation){
		func(o *serviceaudit.Observation) { o.SourceIP = "192.0.2.10" },
		func(o *serviceaudit.Observation) { o.ServiceID = "svc_0123456789ABCDEFGHIJKL" },
		func(o *serviceaudit.Observation) { o.RunID = ""; o.RunNumber = 0 },
		func(o *serviceaudit.Observation) {
			o.VisitorConnectionID = mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
		},
	} {
		bad := o
		change(&bad)
		want := ErrServiceAuditAccess
		if bad.Validate() != nil {
			want = serviceaudit.ErrInvalid
		}
		if _, err = d.IngestIngressServiceObservations(t.Context(), lease.IngressLeaseIdentity, serviceaudit.Batch{Events: []serviceaudit.Observation{bad}}, now); !errors.Is(err, want) {
			t.Fatalf("session denial escaped its bound scope: %v", err)
		}
	}
}

func TestIntegrationServiceAuditCursorFollowsCommitOrder(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	creation := oidcRouteRequest(t, d, now)
	service, err := d.CreateServiceAt(t.Context(), creation.TeamID, creation.ActingIdentityID, "audit-order", "audit-order", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	initial, err := d.ListServiceAudit(t.Context(), creation.TeamID, creation.ActingIdentityID, ServiceAuditFilter{ServiceID: service.ID}, now)
	if err != nil {
		t.Fatal(err)
	}
	after := initial.Events[len(initial.Events)-1].Cursor
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	first, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, first)
	second, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, second)
	e := serviceaudit.Event{TeamID: creation.TeamID, ServiceID: service.ID, ServiceKind: "service", ActorIdentityID: creation.ActingIdentityID, EventType: "apply", OccurredAt: now}
	if err = RecordServiceAudit(ctx, first, e, "first"); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	result := make(chan error, 1)
	workers.Go(func() {
		event := e
		event.EventType = "group.update"
		err := RecordServiceAudit(ctx, second, event, "second")
		if err == nil {
			err = second.Commit(ctx)
		}
		result <- err
	})
	waitForPostgresBlock(t, ctx, d, int32(first.Conn().PgConn().PID()), result)
	page, err := d.ListServiceAudit(ctx, creation.TeamID, creation.ActingIdentityID, ServiceAuditFilter{ServiceID: service.ID, After: after}, now)
	if err != nil || len(page.Events) != 0 {
		t.Fatalf("uncommitted audit visible: %+v %v", page, err)
	}
	if err = first.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = awaitIntegrationResult(t, ctx, result); err != nil {
		t.Fatal(err)
	}
	page, err = d.ListServiceAudit(ctx, creation.TeamID, creation.ActingIdentityID, ServiceAuditFilter{ServiceID: service.ID, After: after, Limit: 1}, now)
	if err != nil || len(page.Events) != 1 || page.Events[0].EventType != "apply" || page.NextCursor == "" {
		t.Fatalf("slow commit skipped: %+v %v", page, err)
	}
	page, err = d.ListServiceAudit(ctx, creation.TeamID, creation.ActingIdentityID, ServiceAuditFilter{ServiceID: service.ID, After: page.NextCursor}, now)
	if err != nil || len(page.Events) != 1 || page.Events[0].EventType != "group.update" {
		t.Fatalf("next commit skipped: %+v %v", page, err)
	}
}

func TestIntegrationServiceAuditDelayedPublisherBatchAfterRevocation(t *testing.T) {
	runs, publishers, _, creation := poolReviewFixtures(t)
	f := runs[0]
	d, now := f.database, f.now
	visitor, _ := opaqueid.New(opaqueid.VisitorConnectionPrefix)
	o := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: f.setup.PublicURLID, ServiceKind: "public_url", EventType: "http.decision", RunID: f.setup.PublishRunID, RunNumber: int64(f.setup.PublishRunNumber), VisitorConnectionID: visitor, SourceIP: "192.0.2.9", OccurredAt: now, Outcome: "allowed"}
	if err := d.RevokePublisherGrant(t.Context(), creation.TeamID, publishers[0].ID, publishers[0].GrantID, creation.ActingIdentityID, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	batch := serviceaudit.Batch{Events: []serviceaudit.Observation{o}}
	if result, err := d.IngestPublisherServiceObservations(t.Context(), f.authentication(), batch, now.Add(30*time.Second)); err != nil || result.Accepted != 1 {
		t.Fatalf("legitimate delayed exact-run batch rejected: %+v %v", result, err)
	}
	if result, err := d.IngestPublisherServiceObservations(t.Context(), f.authentication(), batch, now.Add(31*time.Second)); err != nil || result.Duplicates != 1 {
		t.Fatalf("closed-run retry changed deduplication: %+v %v", result, err)
	}
	o.EventID = serviceaudit.NewID()
	o.OccurredAt = now.Add(2 * time.Second)
	batch.Events = []serviceaudit.Observation{o}
	if _, err := d.IngestPublisherServiceObservations(t.Context(), f.authentication(), batch, now.Add(30*time.Second)); !errors.Is(err, ErrServiceAuditAccess) {
		t.Fatalf("old token manufactured post-revocation activity: %v", err)
	}
	o.OccurredAt = now
	batch.Events = []serviceaudit.Observation{o}
	if _, err := d.IngestPublisherServiceObservations(t.Context(), f.authentication(), batch, now.Add(3*time.Minute)); !errors.Is(err, ErrPublishRunStale) {
		t.Fatalf("late-delivery authority was not bounded: %v", err)
	}
	bad := f.authentication()
	bad.PublishRunToken = runs[1].setup.PublishRunToken
	if _, err := d.IngestPublisherServiceObservations(t.Context(), bad, batch, now.Add(30*time.Second)); !errors.Is(err, ErrPublishRunCredential) {
		t.Fatalf("revoked-run grace accepted another run's token: %v", err)
	}
}

func TestIntegrationServiceAuditCrossTeamClockOrder(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	creation := oidcRouteRequest(t, d, now)
	other, err := d.CreateTeam(t.Context(), CreateTeamRequest{IdentityID: creation.ActingIdentityID, IdempotencyKey: "audit-other-team",
		RequestDigest: sha256.Sum256([]byte("audit-other-team")), DisplayName: "audit-other-team"}, now)
	if err != nil {
		t.Fatal(err)
	}
	teams := []string{creation.TeamID, other.ID}
	sort.Strings(teams)
	var leases []IngressLease
	for _, id := range []string{"audit-clock-a", "audit-clock-b"} {
		lease, err := d.RegisterIngress(t.Context(), IngressRegistration{IngressID: id, IngressRunID: id + "-process", ProtocolVersion: 1, ConnectionCapacity: 10}, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		leases = append(leases, lease)
	}
	var services []ServiceRecord
	for _, team := range teams {
		s, err := d.CreateServiceAt(t.Context(), team, creation.ActingIdentityID, "audit-clock", "audit-clock-"+team, ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"})
		if err != nil {
			t.Fatal(err)
		}
		services = append(services, s)
	}
	// HTTP transport denials derive only service/run/source, never a person.
	var runs []ServiceRunPreparation
	for _, s := range services {
		actor := creation
		actor.TeamID = s.TeamID
		enrollment := publisherEnrollment(t, d, actor, PublisherScope{TeamID: s.TeamID, Kind: "service", ServiceID: s.ID}, now)
		public, _, _ := ed25519.GenerateKey(rand.Reader)
		publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
		if err != nil {
			t.Fatal(err)
		}
		run, err := d.PrepareServiceRun(t.Context(), s.ID, publisher, "audit-clock", now, s.ServiceMetadata)
		if err != nil {
			t.Fatal(err)
		}
		runs = append(runs, run)
	}
	var batches []serviceaudit.Batch
	for index, lease := range leases {
		var batch serviceaudit.Batch
		for serviceIndex, s := range services {
			visitor, _ := opaqueid.New(opaqueid.VisitorConnectionPrefix)
			run := runs[serviceIndex]
			_, err = d.pool.Exec(t.Context(), `INSERT INTO control.direct_service_visitors(visitor_connection_id,service_id,service_run_id,run_number,source_ip,ingress_id,ingress_run_id,ingress_lease_revision,destination_port,valid_until,created_at)
				VALUES($1,$2,$3,$4,'192.0.2.9',$5,$6,$7,25443,$8,$9)`, visitor, s.ID, run.RunID, run.RunNumber, lease.IngressID, lease.IngressRunID, int64(lease.IngressLeaseRevision), now.Add(time.Minute), now)
			if err != nil {
				t.Fatal(err)
			}
			o := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: s.ID, ServiceKind: "service", RunID: run.RunID, RunNumber: run.RunNumber, VisitorConnectionID: visitor, SourceIP: "192.0.2.9", EventType: "connection.open", Outcome: "denied", Reason: "authorization", OccurredAt: now}
			batch.Events = append(batch.Events, o)
		}
		if index == 1 {
			batch.Events[0], batch.Events[1] = batch.Events[1], batch.Events[0]
		}
		batches = append(batches, batch)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	gate, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if err = controlstatedb.New(gate).LockServiceAuditClock(ctx, teams[0]); err != nil {
		t.Fatal(err)
	}
	workers := newIntegrationWorkers(t, cancel)
	defer workers.stop()
	first, second := make(chan error, 1), make(chan error, 1)
	ingest := func(index int, done chan<- error) {
		result, err := d.IngestIngressServiceObservations(ctx, leases[index].IngressLeaseIdentity, batches[index], now)
		if err == nil && result.Accepted != 2 {
			err = errors.New("cross-team batch did not commit both events")
		}
		done <- err
	}
	workers.Go(func() { ingest(0, first) })
	firstPID := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), first)
	workers.Go(func() { ingest(1, second) })
	waitForPostgresBlock(t, ctx, d, firstPID, second)
	// both reporters must wait for the first team without owning the second
	// team's clock, even when their input batches have opposite team order.
	var free bool
	if err = gate.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended('tnl:service-audit:'||$1,0))`, teams[1]).Scan(&free); err != nil || !free {
		t.Fatalf("reporter held a later team's clock: %t %v", free, err)
	}
	if err = gate.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for _, result := range []chan error{first, second} {
		if err = awaitIntegrationResult(t, ctx, result); err != nil {
			t.Fatal(err)
		}
	}
	for index, batch := range batches {
		result, err := d.IngestIngressServiceObservations(ctx, leases[index].IngressLeaseIdentity, batch, now)
		if err != nil || result.Accepted != 0 || result.Duplicates != 2 {
			t.Fatalf("cross-team acknowledgement is not retry-stable: %+v %v", result, err)
		}
	}
}
