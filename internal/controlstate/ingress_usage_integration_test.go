package controlstate

import (
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/routeusage"
)

func TestIntegrationIngressUsage(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "ingress_usage")
	testIngressUsage(t, database)
}

func TestIntegrationCompleteRouteUsageAdvancesObservedThrough(t *testing.T) {
	database, _ := newControlStateIntegrationDatabase(t, "complete_route_usage")
	base := time.Date(2026, time.September, 16, 20, 48, 0, 0, time.UTC)
	seedControlRoute(t, database, base, "usage_complete")
	if _, err := database.pool.Exec(t.Context(), `
		INSERT INTO control.route_sessions (
			id, route_id, team_id, acting_identity_id, route_version,
			idempotency_key, request_digest, session_token_id, session_token_digest,
			policy_revision, certificate_cache_key, certificate_scope,
			certificate_identifiers, certificate_challenge, state,
			created_at, last_heartbeat_at, publisher_expires_at
		) VALUES (
			'session_usage_complete', 'route_usage_complete', 'team_usage_complete', 'identity_usage_complete', 1,
			'usage-complete', decode(repeat('01', 32), 'hex'), 'token_usage_complete', decode(repeat('02', 32), 'hex'),
			1, 'usage-complete', 'usage-complete', ARRAY['route-usage-complete.example.test'], 'dns-01', 'starting',
			$1, $1, $2
		)
	`, base, base.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	lease, err := database.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "ingress_usage_complete", IngressRunID: "run_usage_complete",
		ProtocolVersion: 1, ConnectionCapacity: 10,
	}, base, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	observedThrough := base.Add(30 * time.Second)
	if err := database.ReportIngressUsage(t.Context(), lease.IngressLeaseIdentity, IngressUsageBatch{
		Reports: []IngressUsageReport{{
			RouteID: "route_usage_complete", RouteVersion: 1,
			BucketStart: base, BucketEnd: base.Add(time.Minute), ObservedThrough: observedThrough,
			ReportRevision: 1, ConnectionAttempts: 1,
			HistogramData: (routeusage.Checkpoint{}).MarshalBinary(), Final: true,
		}},
		ObservedThrough: &observedThrough,
		Complete:        true,
	}, observedThrough.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if finalized, err := database.FinalizeRouteUsageBuckets(
		t.Context(), base.Add(time.Minute), base.Add(time.Minute),
	); err != nil || finalized != 1 {
		t.Fatalf("finalize route usage = %d, %v", finalized, err)
	}

	work, err := database.ClaimRouteUsageDeliveries(
		t.Context(), "usage_worker_complete", 32, base.Add(61*time.Second), time.Minute,
	)
	if err != nil || len(work) != 1 {
		t.Fatalf("claim route usage = %#v, %v", work, err)
	}
	if !work[0].Complete || !work[0].ObservedThrough.Equal(work[0].BucketEnd) {
		t.Fatalf("complete route usage = %#v", work[0])
	}
}
