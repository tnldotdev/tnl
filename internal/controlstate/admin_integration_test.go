package controlstate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
)

func TestIntegrationAdministrationState(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "administration")
	session, err := database.CreateBuiltinControlSession(
		t.Context(), "managed.example.test", 1, time.Hour, 24*time.Hour, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	actor := session.Identity.Identity.ID
	registration := RelayRegistration{
		RelayServiceID: "relay_service_a", RelayID: "relay_a", RelayRunID: "run_a", ProtocolVersion: 1,
		RelayAddress: "relay-a.example:443", TLSServerName: "relay-a.example",
		InternalRelayAddress: "relay-a.internal:9443", ConnectionCapacity: 10, StreamCapacity: 20,
	}
	lease, err := database.RegisterRelay(t.Context(), registration, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	registration.RelayServiceID, registration.RelayID, registration.RelayRunID = "relay_service_b", "relay_b", "run_b"
	registration.RelayAddress, registration.TLSServerName = "relay-b.example:443", "relay-b.example"
	registration.InternalRelayAddress = "relay-b.internal:9443"
	if _, err := database.RegisterRelay(t.Context(), registration, now, time.Minute); err != nil {
		t.Fatal(err)
	}

	counts, err := database.AdminRuntimeCounts(t.Context(), now)
	if err != nil || counts.RelayLeases != 2 {
		t.Fatalf("admin counts = %#v, %v", counts, err)
	}
	page, err := database.ListAdminRelayLeases(t.Context(), "relay_a", now)
	if err != nil || len(page.Relays) != 1 || page.Relays[0].RelayID != "relay_b" || page.NextCursor != "" {
		t.Fatalf("relay page = %#v, %v", page, err)
	}
	if _, err := database.ListAdminRelayLeases(t.Context(), " relay_a ", now); !errors.Is(err, ErrAdminInvalid) {
		t.Fatalf("invalid cursor error = %v", err)
	}

	deadline := now.Add(30 * time.Second)
	drained, err := database.BeginAdminRelayDrain(
		t.Context(), lease.RelayLeaseIdentity, actor, "request_drain", now.Add(time.Second), deadline,
	)
	if err != nil || !drained.Draining || drained.DrainDeadline == nil || !drained.DrainDeadline.Equal(deadline) ||
		!drained.LeaseExpiresAt.Equal(deadline) {
		t.Fatalf("drained relay = %#v, %v", drained, err)
	}
	renewed, err := database.RenewRelay(t.Context(), RelayRenewal{
		RelayLeaseIdentity: lease.RelayLeaseIdentity, ReportedConnections: 3, ReportedStreams: 4,
	}, now.Add(2*time.Second), time.Minute)
	if err != nil || !renewed.Draining || !renewed.LeaseExpiresAt.Equal(deadline) ||
		renewed.ReportedConnections != lease.ReportedConnections || renewed.ReportedStreams != lease.ReportedStreams {
		t.Fatalf("renewed draining relay = %#v, %v", renewed, err)
	}
	repeated, err := database.RegisterRelay(t.Context(), RelayRegistration{
		RelayServiceID: "relay_service_a", RelayID: "relay_a", RelayRunID: "run_a", ProtocolVersion: 1,
		RelayAddress: "relay-a.example:443", TLSServerName: "relay-a.example",
		InternalRelayAddress: "relay-a.internal:9443", ConnectionCapacity: 10, StreamCapacity: 20,
	}, now.Add(3*time.Second), time.Minute)
	if err != nil || !repeated.Draining || !repeated.LeaseExpiresAt.Equal(deadline) {
		t.Fatalf("re-registered draining relay = %#v, %v", repeated, err)
	}
	if _, err := database.BeginAdminRelayDrain(
		t.Context(), lease.RelayLeaseIdentity, actor, "request_repeat", now.Add(4*time.Second), deadline,
	); !errors.Is(err, ErrRelayLeaseStale) {
		t.Fatalf("repeated drain error = %v", err)
	}

	controls, err := database.ListMaintenanceControls(t.Context())
	if err != nil || len(controls) != 3 {
		t.Fatalf("maintenance controls = %#v, %v", controls, err)
	}
	updated, err := database.SetMaintenanceControl(
		t.Context(), MaintenanceControlPublicURLCreation, false, actor, "request_maintenance", now.Add(5*time.Second),
	)
	if err != nil || updated.Allowed || updated.Revision != 2 || updated.UpdatedBy != actor {
		t.Fatalf("updated maintenance control = %#v, %v", updated, err)
	}
	if _, err := database.SetMaintenanceControl(
		t.Context(), "unknown", false, actor, "request_unknown", now.Add(6*time.Second),
	); !errors.Is(err, ErrAdminInvalid) {
		t.Fatalf("unknown maintenance control error = %v", err)
	}

	var auditCount int
	if err := database.pool.QueryRow(t.Context(), `
		SELECT count(*)
		FROM control.admin_audit_events
		WHERE actor_identity_id = $1
		  AND request_id IN ('request_drain', 'request_maintenance')
	`, actor).Scan(&auditCount); err != nil || auditCount != 2 {
		t.Fatalf("admin audit count = %d, %v", auditCount, err)
	}
}

func TestIntegrationMaintenanceControlReadersShareGate(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "maintenance_readers")
	session := newBuiltinSession(t, database, now)
	actor := session.Identity.Identity.ID
	tests := []struct {
		name  MaintenanceControlName
		guard func(context.Context, *controlstatedb.Queries) (bool, error)
	}{
		{MaintenanceControlPublicURLCreation, func(ctx context.Context, queries *controlstatedb.Queries) (bool, error) {
			return queries.LockPublicURLCreationControl(ctx)
		}},
		{MaintenanceControlPublishRunCreation, func(ctx context.Context, queries *controlstatedb.Queries) (bool, error) {
			return queries.LockPublishRunCreationControl(ctx)
		}},
		{MaintenanceControlCertificateIssuance, func(ctx context.Context, queries *controlstatedb.Queries) (bool, error) {
			return queries.LockCertificateIssuanceControl(ctx)
		}},
	}
	for _, test := range tests {
		t.Run(string(test.name), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			first, err := database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, first)
			if enabled, err := test.guard(ctx, controlstatedb.New(first)); err != nil || !enabled {
				t.Fatalf("first maintenance reader = %t, %v", enabled, err)
			}
			second, err := database.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, second)
			if _, err := second.Exec(ctx, `SET LOCAL lock_timeout = '100ms'`); err != nil {
				t.Fatal(err)
			}
			if enabled, err := test.guard(ctx, controlstatedb.New(second)); err != nil || !enabled {
				t.Fatalf("concurrent maintenance reader = %t, %v", enabled, err)
			}
			workers := newIntegrationWorkers(t, cancel)
			updated := make(chan error, 1)
			workers.Go(func() {
				_, err := database.SetMaintenanceControl(ctx, test.name, false, actor, "disable_"+string(test.name), now.Add(time.Second))
				updated <- err
			})
			waitForPostgresBlock(t, ctx, database, int32(first.Conn().PgConn().PID()), updated)
			if err := first.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			waitForPostgresBlock(t, ctx, database, int32(second.Conn().PgConn().PID()), updated)
			if err := second.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, updated); err != nil {
				t.Fatal(err)
			}
			if enabled, err := test.guard(ctx, controlstatedb.New(database.pool)); err != nil || enabled {
				t.Fatalf("maintenance reader after disable = %t, %v", enabled, err)
			}
			if _, err := database.SetMaintenanceControl(ctx, test.name, true, actor, "enable_"+string(test.name), now.Add(2*time.Second)); err != nil {
				t.Fatal(err)
			}
		})
	}
}
