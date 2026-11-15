package state

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
)

func TestIntegrationGuestIngressAuditRetainsTeamlessOwnership(t *testing.T) {
	f, guest := guestAuthorityFixture(t, true)
	ctx := t.Context()
	ingress, err := f.database.RegisterIngress(ctx, IngressRegistration{
		IngressID: "guest-audit", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix),
		ProtocolVersion: 1, HTTPS: true, ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID,
	}, f.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	visitor := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
	routing, err := readIngressServiceRun(ctx, f.database, ingress.IngressLeaseIdentity, f.service.ID, f.run.RunID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	denial := serviceaudit.Observation{
		EventID: serviceaudit.NewID(), ServiceID: f.service.ID, ServiceKind: "service",
		VisitorConnectionID: visitor, SourceIP: "192.0.2.10", EventType: "connection.open",
		Outcome: "denied", Reason: "capacity", OccurredAt: f.now, RoutingAuthority: routing.SourceAuthority,
	}
	forwarded := denial
	forwarded.EventID, forwarded.RunID, forwarded.RunNumber = serviceaudit.NewID(), f.run.RunID, f.run.RunNumber
	forwarded.Outcome, forwarded.Reason, forwarded.RoutingAuthority = "allowed", "", nil
	batch := serviceaudit.Batch{Events: []serviceaudit.Observation{denial, denial}}
	result, err := f.database.IngestIngressServiceObservations(ctx, ingress.IngressLeaseIdentity, batch, f.now)
	if err != nil || result.Accepted != 1 || result.Duplicates != 1 {
		t.Fatal("teamless ingress denial did not commit once", result, err)
	}
	result, err = f.database.IngestServiceRunObservations(ctx, f.service.ID, f.run.RunID, f.run.Token, f.run.RunNumber,
		serviceaudit.Batch{Events: []serviceaudit.Observation{forwarded, forwarded}}, f.now)
	if err != nil || result.Accepted != 1 || result.Duplicates != 1 {
		t.Fatal("teamless publisher connection did not commit once", result, err)
	}
	var count int
	if err := f.database.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_audit_events
		WHERE id=ANY($1) AND team_id IS NULL AND guest_id=$2 AND service_id=$3 AND host(source_ip)=$4`,
		[]string{denial.EventID, forwarded.EventID}, guest.ID, f.service.ID, denial.SourceIP).Scan(&count); err != nil || count != 2 {
		t.Fatal("ingress observations lost the actual guest owner", count, err)
	}
	denial.EventID, denial.ServiceID = serviceaudit.NewID(), mustOpaqueID(t, opaqueid.ServicePrefix)
	if _, err := f.database.IngestIngressServiceObservations(ctx, ingress.IngressLeaseIdentity,
		serviceaudit.Batch{Events: []serviceaudit.Observation{denial}}, f.now); !errors.Is(err, ErrServiceAuditAccess) {
		t.Fatal("teamless audit bypassed its signed service owner", err)
	}
}

func TestIntegrationGuestAuditLocksOwnerBeforeIngressAndRun(t *testing.T) {
	for _, test := range []struct{ reporter, parent string }{
		{"ingress", "trial"}, {"ingress", "service"}, {"publisher", "trial"}, {"publisher", "service"},
	} {
		t.Run(test.reporter+"/"+test.parent, func(t *testing.T) {
			f, _ := guestAuthorityFixture(t, true)
			ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
			defer cancel()
			ingress, err := f.database.RegisterIngress(ctx, IngressRegistration{
				IngressID: "audit-order", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix),
				ProtocolVersion: 1, HTTPS: true, ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID,
			}, f.now, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			visitor := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
			routing, err := readIngressServiceRun(ctx, f.database, ingress.IngressLeaseIdentity, f.service.ID, f.run.RunID, f.now)
			if err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			gate, err := f.database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			q := controlstatedb.New(gate)
			if test.parent == "trial" {
				_, err = q.LockGuestTrialByID(ctx, f.guest.ID)
			} else {
				_, err = q.LockService(ctx, f.service.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			event := serviceaudit.Observation{
				EventID: serviceaudit.NewID(), ServiceID: f.service.ID, ServiceKind: "service",
				RunID: f.run.RunID, RunNumber: f.run.RunNumber,
				VisitorConnectionID: visitor, SourceIP: "192.0.2.10", EventType: "connection.open",
				Outcome: "denied", Reason: "capacity", OccurredAt: f.now,
			}
			if test.reporter == "publisher" {
				event.EventType, event.Outcome, event.Reason = "http.decision", "allowed", ""
			} else {
				event.RunID, event.RunNumber, event.RoutingAuthority = "", 0, routing.SourceAuthority
			}
			batch := serviceaudit.Batch{Events: []serviceaudit.Observation{event}}
			done := make(chan error, 1)
			workers.Go(func() {
				var result ServiceObservationResult
				var err error
				if test.reporter == "ingress" {
					result, err = f.database.IngestIngressServiceObservations(ctx, ingress.IngressLeaseIdentity, batch, f.now)
				} else {
					result, err = f.database.IngestServiceRunObservations(ctx, f.service.ID, f.run.RunID, f.run.Token, f.run.RunNumber, batch, f.now)
				}
				if err == nil && result.Accepted != 1 {
					err = errors.New("guest audit did not retain its report")
				}
				done <- err
			})
			waitForPostgresBlock(t, ctx, f.database, int32(gate.Conn().PgConn().PID()), done)
			// a heartbeat holds the trial before its run; admission holds it
			// before ingress. neither child may be held by this blocked reporter.
			if _, err := gate.Exec(ctx, `SELECT id FROM control.service_runs WHERE id=$1 FOR UPDATE NOWAIT`, f.run.RunID); err != nil {
				t.Fatal("audit locked the run before its guest owner", err)
			}
			if _, err := gate.Exec(ctx, `SELECT ingress_id FROM control.ingress_leases WHERE ingress_id=$1 FOR UPDATE NOWAIT`, ingress.IngressID); err != nil {
				t.Fatal("audit locked ingress before its guest owner", err)
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}
