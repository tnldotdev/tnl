package state

import (
	"errors"
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

func TestIntegrationEphemeralExpiryQueuesManagedEndpointDNSRemoval(t *testing.T) {
	d, now, authority, leases := newPublishRunPrerequisites(t)
	ctx := t.Context()
	service, err := d.CreateServiceAt(ctx, authority.TeamID, authority.ActingIdentityID, "temporary-dns", "temporary-dns",
		ServicePlacement{DNSAutomation: true}, now, ServiceMetadata{Protocol: "http"},
		&ProjectServiceConfiguration{Target: "localhost:3000", Public: new(true), Ephemeral: true})
	if err != nil {
		t.Fatal(err)
	}
	// creation advances its authorization clock while acquiring locks.
	now = now.Add(time.Second)
	publisher, prepared := adminPreparedRun(t, d, service, authority.ActingIdentityID, now)
	run, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	f := servicePublicationFixture{database: d, now: now, service: service, publisher: publisher, prepared: prepared, run: run, leases: leases}
	registerServingIngress(t, f, "ephemeral-dns", now)
	prepareServingPublisher(t, f)
	// retain the old worker's advertised lifetime across automatic expiry so
	// the stale acknowledgment exercises the retired revision, not validation.
	published, found, err := d.ClaimServiceEndpointDNSWork(ctx, "ephemeral-dns", now, ephemeralServiceGracePeriod+time.Minute)
	if err != nil || !found || published.ServiceID != service.ID || published.Hostname != service.Endpoint.Hostname ||
		published.State != ServiceEndpointDNSPending || !published.Public {
		t.Fatal("ready ephemeral service did not queue its managed DNS publication", published, found, err)
	}
	published.State, published.AvailableAt = ServiceEndpointDNSPublished, time.Time{}
	if _, err := d.SaveServiceEndpointDNSWork(ctx, published, now); err != nil {
		t.Fatal(err)
	}
	closedAt := now.Add(time.Second)
	if err := d.CloseServiceRun(ctx, service.ID, run.RunID, run.Token, closedAt); err != nil {
		t.Fatal(err)
	}
	if count, err := d.ExpireServiceRuns(ctx, closedAt.Add(ephemeralServiceGracePeriod-time.Second)); err != nil || count != 0 {
		t.Fatal("ephemeral service expired before its idle grace", count, err)
	}
	expiredAt := closedAt.Add(ephemeralServiceGracePeriod + time.Second)
	if count, err := d.ExpireServiceRuns(ctx, expiredAt); err != nil || count != 1 {
		t.Fatal("idle ephemeral service did not expire", count, err)
	}
	var retired bool
	if err := d.pool.QueryRow(ctx, `SELECT service.deleted_at IS NOT NULL AND NOT service.enabled
		AND endpoint.retired_at IS NOT NULL AND endpoint.dns_automation AND endpoint.dns_state='removing'
		FROM control.services service JOIN control.service_endpoints endpoint ON endpoint.service_id=service.id
		WHERE service.id=$1`, service.ID).Scan(&retired); err != nil || !retired {
		t.Fatal("automatic expiry did not retain managed DNS cleanup", err)
	}
	cleanupAt := expiredAt.Add(time.Second)
	removal, found, err := d.ClaimServiceEndpointDNSWork(ctx, "ephemeral-cleanup", cleanupAt, time.Minute)
	if err != nil || !found || removal.ServiceID != service.ID || removal.Hostname != published.Hostname ||
		removal.State != ServiceEndpointDNSRemoving || removal.Public != published.Public {
		t.Fatal("expired endpoint DNS removal was not claimable", removal, found, err)
	}
	if err := d.ValidateServiceEndpointDNSWork(ctx, removal, cleanupAt); err != nil {
		t.Fatal("automatic removal claim was not current", err)
	}
	if _, err := d.SaveServiceEndpointDNSWork(ctx, published, cleanupAt); !errors.Is(err, ErrServiceEndpointDNSWorkStale) {
		t.Fatal("old publication acknowledgment revived expired DNS", err)
	}
	removal.State, removal.AvailableAt = ServiceEndpointDNSRemoved, time.Time{}
	if _, err := d.SaveServiceEndpointDNSWork(ctx, removal, cleanupAt); err != nil {
		t.Fatal(err)
	}
	if count, err := d.ExpireServiceRuns(ctx, cleanupAt.Add(time.Second)); err != nil || count != 0 {
		t.Fatal("automatic expiry repeated a terminal deletion", count, err)
	}
	if _, found, err := d.ClaimServiceEndpointDNSWork(ctx, "ephemeral-cleanup", cleanupAt.Add(time.Second), time.Minute); err != nil || found {
		t.Fatal("completed automatic DNS removal remained queued", found, err)
	}
}
