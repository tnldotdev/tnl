package state

import (
	"fmt"
	"testing"
	"time"
)

func TestIntegrationEphemeralCleanupRestoredMixedEnabledStateAndAudit(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "restored_ephemeral_cleanup")
	ctx := t.Context()
	session := newOIDCSession(t, d, now)
	team, actor := session.Identity.Memberships[0].TeamID, session.Identity.Identity.ID
	var ids []string
	for _, enabled := range []bool{true, false} {
		name := fmt.Sprintf("ephemeral-%t", enabled)
		service, err := d.CreateServiceAt(ctx, team, actor, name, name, ServicePlacement{}, now,
			ServiceMetadata{Protocol: "http"}, &ProjectServiceConfiguration{Target: "localhost:3000", Ephemeral: true})
		if err != nil {
			t.Fatal(err)
		}
		if !enabled {
			if _, err := d.SetServiceEnabled(ctx, service.ID, actor, false, now); err != nil {
				t.Fatal(err)
			}
		}
		ids = append(ids, service.ID)
	}
	var enabled, disabled int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE enabled),count(*) FILTER(WHERE NOT enabled)
		FROM control.services WHERE id=ANY($1::text[]) AND ephemeral AND deleted_at IS NULL`, ids).Scan(&enabled, &disabled); err != nil ||
		enabled != 1 || disabled != 1 {
		t.Fatal("expiry fixture is not one enabled and one disabled ephemeral service", enabled, disabled, err)
	}
	at := now.Add(ephemeralServiceGracePeriod + time.Second)
	for attempt, want := range []int{2, 0} {
		count, err := d.ExpireServiceRuns(ctx, at)
		if err != nil || count != want {
			t.Fatalf("mixed expiry attempt %d count=%d want=%d: %v", attempt, count, want, err)
		}
		var deleted, cleaned, audited, distinctAudited int
		if err := d.pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM control.services WHERE id=ANY($1::text[]) AND deleted_at IS NOT NULL AND NOT enabled),
			(SELECT count(*) FROM control.service_endpoints WHERE service_id=ANY($1::text[]) AND retired_at IS NOT NULL AND dns_state='removed'),
			(SELECT count(*) FROM control.service_audit_events WHERE service_id=ANY($1::text[]) AND event_type='service.delete'),
			(SELECT count(DISTINCT service_id) FROM control.service_audit_events WHERE service_id=ANY($1::text[]) AND event_type='service.delete')`,
			ids).Scan(&deleted, &cleaned, &audited, &distinctAudited); err != nil ||
			deleted != 2 || cleaned != 2 || audited != 2 || distinctAudited != 2 {
			t.Fatalf("mixed expiry deleted/cleaned/audited/distinct=%d/%d/%d/%d, want 2/2/2/2: %v",
				deleted, cleaned, audited, distinctAudited, err)
		}
	}
}
