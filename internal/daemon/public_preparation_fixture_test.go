package daemon

import (
	"context"
	"crypto/tls"
	"database/sql"
	"net"
	"net/url"
	"testing"
	"time"
)

// readiness and routing precede background policy and capacity preparation.
// verify visitor TLS without contacting the local application.
func waitForPreparedPublicVisitor(t *testing.T, visitor *integrationVisitor, address string) {
	t.Helper()
	endpoint, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	waitForIntegrationCondition(t, 15*time.Second, func(ctx context.Context) (bool, error) {
		target := net.JoinHostPort(endpoint.Hostname(), "443")
		dial := visitor.transport.DialContext
		if dial == nil {
			dial = new(net.Dialer).DialContext
		}
		connection, err := dial(ctx, "tcp", target)
		if err != nil {
			return false, err
		}
		defer connection.Close()
		configuration := visitor.transport.TLSClientConfig.Clone()
		configuration.ServerName = endpoint.Hostname()
		secured := tls.Client(connection, configuration)
		defer secured.Close()
		err = secured.HandshakeContext(ctx)
		return err == nil, err
	})
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
			'publisher_observed_at',publisher_observed_at,'retired_at',retired_at
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
