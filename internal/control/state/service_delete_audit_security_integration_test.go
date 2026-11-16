package state

import (
	"reflect"
	"testing"
	"time"
)

func TestIntegrationServiceDeletionLateAuditFailureRollsBackActivePublication(t *testing.T) {
	d, now, authority, leases := newPublishRunPrerequisites(t)
	ctx := t.Context()
	service, err := d.CreateServiceAt(ctx, authority.TeamID, authority.ActingIdentityID, "delete-audit", "delete-audit",
		ServicePlacement{DNSAutomation: true}, now, ServiceMetadata{},
		&ProjectServiceConfiguration{Protocol: "tcp", Target: "localhost:3000", Public: new(true)})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	publisher, prepared := adminPreparedRun(t, d, service, authority.ActingIdentityID, now)
	run, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	f := servicePublicationFixture{database: d, now: now, service: service, publisher: publisher, prepared: prepared, run: run, leases: leases}
	f.readyConnections(t, now)
	var active bool
	if err := d.pool.QueryRow(ctx, `SELECT
		(SELECT count(*)=2 FROM control.service_connection_slots WHERE service_run_id=$1 AND session_open AND state='ready')
		AND EXISTS(SELECT 1 FROM control.service_port_claims WHERE service_id=$2 AND state='held')
		AND EXISTS(SELECT 1 FROM control.service_endpoints WHERE service_id=$2 AND retired_at IS NULL AND dns_state='pending')`,
		run.RunID, service.ID).Scan(&active); err != nil || !active {
		t.Fatal("deletion fixture lacks active slots, a public port, or managed DNS work", err)
	}
	before := serviceSecuritySnapshot(t, d)
	for _, statement := range []string{
		`CREATE FUNCTION control.reject_service_delete_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NOT EXISTS(SELECT 1 FROM control.services WHERE id=NEW.service_id AND deleted_at IS NOT NULL AND NOT enabled)
				OR EXISTS(SELECT 1 FROM control.service_runs WHERE service_id=NEW.service_id AND closed_at IS NULL)
				OR EXISTS(SELECT 1 FROM control.service_connection_slots WHERE service_id=NEW.service_id AND session_open)
				OR NOT EXISTS(SELECT 1 FROM control.service_port_claims WHERE service_id=NEW.service_id AND state='quarantined')
				OR NOT EXISTS(SELECT 1 FROM control.service_endpoints WHERE service_id=NEW.service_id AND retired_at IS NOT NULL AND dns_state='removing')
				OR NOT EXISTS(SELECT 1 FROM control.service_audit_events WHERE service_id=NEW.service_id AND event_type='run.close') THEN
				RAISE EXCEPTION 'delete audit preceded publication retirement' USING ERRCODE='P0001';
			END IF;
			RAISE EXCEPTION 'late service delete audit failure'
				USING ERRCODE='23514',CONSTRAINT='reject_service_delete_audit',DETAIL='publication retirement observed';
		END; $$`,
		`CREATE TRIGGER reject_service_delete_audit BEFORE INSERT ON control.service_audit_events
			FOR EACH ROW WHEN (NEW.event_type='service.delete') EXECUTE FUNCTION control.reject_service_delete_audit()`,
	} {
		if _, err := d.pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	err = d.DeleteService(ctx, service.ID, authority.ActingIdentityID, now)
	requireRestoredPostgresFailure(t, err, "23514", "reject_service_delete_audit", "publication retirement observed")
	if after := serviceSecuritySnapshot(t, d); !reflect.DeepEqual(after, before) {
		t.Fatal("failed actual deletion retained closure, tombstone, port/DNS retirement, policy, or audit changes")
	}
	if saved, err := d.GetService(ctx, service.ID, authority.ActingIdentityID); err != nil || !saved.Enabled {
		t.Fatal("failed deletion lost current management authority", err)
	}
	if _, err := d.pool.Exec(ctx, `DROP TRIGGER reject_service_delete_audit ON control.service_audit_events`); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteService(ctx, service.ID, authority.ActingIdentityID, now); err != nil {
		t.Fatal("failed deletion could not retry through its ordinary owner", err)
	}
	var deleted bool
	if err := d.pool.QueryRow(ctx, `SELECT service.deleted_at IS NOT NULL AND NOT service.enabled
		AND run.closed_at IS NOT NULL AND NOT run.assignments_open
		AND NOT EXISTS(SELECT 1 FROM control.service_connection_slots WHERE service_run_id=run.id AND session_open)
		AND EXISTS(SELECT 1 FROM control.service_port_claims WHERE service_id=service.id AND state='quarantined')
		AND EXISTS(SELECT 1 FROM control.service_endpoints WHERE service_id=service.id AND retired_at IS NOT NULL AND dns_state='removing')
		AND (SELECT count(*)=1 FROM control.service_audit_events WHERE service_id=service.id AND event_type='service.delete')
		AND (SELECT count(*)=1 FROM control.service_audit_events WHERE run_id=run.id AND event_type='run.close')
		FROM control.services service JOIN control.service_runs run ON run.service_id=service.id WHERE run.id=$1`,
		run.RunID).Scan(&deleted); err != nil || !deleted {
		t.Fatal("successful delete retry lost its exact closure, endpoint retirement, or single audits", err)
	}
	assertAssignmentTotals(t, d.pool, 0)
}
