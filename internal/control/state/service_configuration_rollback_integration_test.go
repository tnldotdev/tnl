package state

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationServiceConfigurationAccessAndPolicyRollBackOnAuditFailure(t *testing.T) {
	f := newServicePublicationFixture(t)
	ctx, d := t.Context(), f.database
	q := controlstatedb.New(d.pool)
	replacement, digest, err := d.GetServiceConfiguration(ctx, f.service.ID, f.actor(t))
	if err != nil || replacement == nil {
		t.Fatal("fixture has no saved service configuration", err)
	}
	replacement.HTTP = &config.HTTPService{Access: &config.Access{Mode: "anonymous", IP: []string{"192.0.2.0/24"}}}
	revision, err := q.ReadVisitorPolicyRevision(ctx, f.service.ID)
	if err != nil {
		t.Fatal(err)
	}
	history := func() []controlstatedb.ReadVisitorPolicyEventsRow {
		t.Helper()
		events, err := q.ReadVisitorPolicyEvents(ctx, controlstatedb.ReadVisitorPolicyEventsParams{ResourceID: f.service.ID, AfterRevision: 0})
		if err != nil {
			t.Fatal(err)
		}
		return events
	}
	snapshot := func() string {
		t.Helper()
		var result string
		if err := d.pool.QueryRow(ctx, `SELECT jsonb_build_object(
			'service',(SELECT to_jsonb(s) FROM control.services s WHERE id=$1),
			'policy',(SELECT to_jsonb(p) FROM control.visitor_policies p WHERE resource_id=$1),
			'runs',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM control.service_runs r WHERE service_id=$1),
			'slots',(SELECT jsonb_agg(to_jsonb(s) ORDER BY publisher_connection_id) FROM control.service_connection_slots s WHERE service_id=$1),
			'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY cursor) FROM control.service_audit_events a WHERE service_id=$1))::text`,
			f.service.ID).Scan(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	before, beforeHistory := snapshot(), history()
	// the fault observes the real policy trigger before rejecting the update's
	// audit. a failure before the access mutation would not satisfy this proof.
	for _, statement := range []string{
		fmt.Sprintf(`CREATE FUNCTION control.reject_access_audit() RETURNS trigger LANGUAGE plpgsql AS $$
			DECLARE current_revision bigint;
			BEGIN
				SELECT revision INTO current_revision FROM control.visitor_policies WHERE resource_id=NEW.service_id;
				IF current_revision IS DISTINCT FROM %d THEN
					RAISE EXCEPTION 'audit preceded the expected access invalidation' USING ERRCODE='P0001';
				END IF;
				RAISE EXCEPTION 'late access audit failure'
					USING ERRCODE='23514',CONSTRAINT='reject_access_audit',DETAIL='policy invalidation observed';
			END; $$`, revision+1),
		`CREATE TRIGGER reject_access_audit BEFORE INSERT ON control.service_audit_events
			FOR EACH ROW WHEN (NEW.event_type='service.update') EXECUTE FUNCTION control.reject_access_audit()`,
	} {
		if _, err := d.pool.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	_, err = d.ConfigureService(ctx, f.service.ID, f.actor(t), f.service.ServiceMetadata, replacement,
		ServiceUpdateConditions{ConfigurationDigest: digest}, f.now)
	requireRestoredPostgresFailure(t, err, "23514", "reject_access_audit", "policy invalidation observed")
	if snapshot() != before || !reflect.DeepEqual(history(), beforeHistory) {
		t.Fatal("failed configuration update retained settings, policy, history, run, slot, or audit changes")
	}
	mode, err := d.serviceHTTPSourcePolicy(ctx, q, f.service.ID, netip.MustParseAddr("192.0.2.8"))
	if err != nil || mode != VisitorAccessRestricted {
		t.Fatal("failed access edit changed the visitor's actual policy", mode, err)
	}
	if _, err := d.pool.Exec(ctx, `DROP TRIGGER reject_access_audit ON control.service_audit_events`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ConfigureService(ctx, f.service.ID, f.actor(t), f.service.ServiceMetadata, replacement,
		ServiceUpdateConditions{ConfigurationDigest: digest}, f.now); err != nil {
		t.Fatal("failed edit consumed the observed configuration fingerprint", err)
	}
	mode, err = d.serviceHTTPSourcePolicy(ctx, q, f.service.ID, netip.MustParseAddr("192.0.2.8"))
	if err != nil || mode != VisitorAccessAnonymous {
		t.Fatal("successful retry did not commit its actual access change", mode, err)
	}
	current, err := q.ReadVisitorPolicyRevision(ctx, f.service.ID)
	afterHistory := history()
	if err != nil || current != revision+1 || len(afterHistory) != len(beforeHistory)+1 ||
		!reflect.DeepEqual(afterHistory[:len(beforeHistory)], beforeHistory) {
		t.Fatal("successful retry did not append exactly one policy invalidation", current, err)
	}
	var audits int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_audit_events
		WHERE service_id=$1 AND event_type='service.update'`, f.service.ID).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("successful retry did not commit exactly one configuration audit", audits, err)
	}
}
