package daemon

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

func readIntegrationServingPreparation(ctx context.Context, database *sql.DB) (string, error) {
	var snapshot string
	err := database.QueryRowContext(ctx, `SELECT jsonb_build_object(
		'observed_at',clock_timestamp(),
		'runs',(SELECT jsonb_agg(facts) FROM (SELECT id,public_url_id,publish_run_number,state,publisher_expires_at,ready_at,certificate_installed_at,certificate_not_after FROM control.publish_runs ORDER BY created_at DESC LIMIT 16) facts),
		'slots',(SELECT jsonb_agg(facts) FROM (SELECT publish_run_id,publisher_connection_id,state,session_open,connected_relay_id,connected_relay_run_id,connected_relay_lease_revision FROM control.publish_run_connection_slots ORDER BY publisher_connection_id LIMIT 32) facts),
		'allocations',(SELECT jsonb_agg(facts) FROM (SELECT id,resource_id,run_id,run_number,ingress_id,ingress_run_id,ingress_lease_revision,valid_until,publisher_observed_until,ingress_observed_until,retired_at FROM control.stream_capacity_allocations ORDER BY id LIMIT 32) facts),
		'ingresses',(SELECT jsonb_agg(facts) FROM (SELECT ingress_id,ingress_run_id,ingress_lease_revision,ingress_pool_id,connector_only,draining,protocol_version,connection_capacity,routing_table_revision,lease_expires_at FROM control.ingress_leases ORDER BY ingress_id LIMIT 16) facts),
		'relays',(SELECT jsonb_agg(facts) FROM (SELECT relay_id,relay_run_id,relay_lease_revision,draining,lease_expires_at FROM control.relay_leases ORDER BY relay_id LIMIT 16) facts),
		'routing_revision',(SELECT max(id) FROM control.ingress_routing_table_events)
	)::text`).Scan(&snapshot)
	return snapshot, err
}

// process leases and allocations renew independently. retain both deadlines
// without treating a later passing run as a cause for an earlier outage EOF.
func logIntegrationPublishRunAuthority(t *testing.T, database *sql.DB, publicURLID string, number uint64, phase string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var snapshot string
	err := database.QueryRowContext(ctx, `SELECT jsonb_build_object(
		'observed_at',clock_timestamp(),
		'allocations',COALESCE((SELECT jsonb_agg(jsonb_build_object(
			'id',id,'ingress_id',ingress_id,'ingress_run_id',ingress_run_id,
			'ingress_lease_revision',ingress_lease_revision,'capacity',capacity,
			'renewed_at',renewed_at,'valid_until',valid_until,
			'publisher_observed_until',publisher_observed_until,'retired_at',retired_at
		) ORDER BY id) FROM control.stream_capacity_allocations
			WHERE run_id=(SELECT id FROM control.publish_runs WHERE public_url_id=$1 AND publish_run_number=$2)),'[]'::jsonb),
		'ingress_leases',COALESCE((SELECT jsonb_agg(jsonb_build_object(
			'id',ingress_id,'run_id',ingress_run_id,'revision',ingress_lease_revision,
			'renewed_at',renewed_at,'expires_at',lease_expires_at,'draining',draining
		) ORDER BY ingress_id) FROM control.ingress_leases),'[]'::jsonb),
		'relay_leases',COALESCE((SELECT jsonb_agg(jsonb_build_object(
			'id',relay_id,'run_id',relay_run_id,'revision',relay_lease_revision,
			'renewed_at',renewed_at,'expires_at',lease_expires_at,'draining',draining
		) ORDER BY relay_id) FROM control.relay_leases),'[]'::jsonb)
	)::text`, publicURLID, number).Scan(&snapshot)
	t.Logf("serving authority phase=%s snapshot=%s query_error=%v", phase, snapshot, err)
}
