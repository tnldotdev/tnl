package controlstate

import (
	"errors"
	"testing"
	"time"
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
		t.Context(), MaintenanceControlRouteCreation, false, actor, "request_maintenance", now.Add(5*time.Second),
	)
	if err != nil || updated.Enabled || updated.Revision != 2 || updated.UpdatedBy != actor {
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
