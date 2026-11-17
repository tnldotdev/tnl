package daemon

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// capture the failed publisher's state before the group cancels its processes.
// select only non-secret fields; the disposable database disappears on cleanup.
func captureSeparatedPublisherFailure(database *sql.DB, index int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var state string
	err := database.QueryRowContext(ctx, `SELECT jsonb_build_object(
		'service_id', r.id, 'hostname', r.certificate_hostname, 'run_id', s.id, 'run_number', s.run_number, 'run_state', s.state,
		'run_created_at', s.created_at, 'run_ready_at', s.ready_at,
		'certificate_installed_at', o.installed_at,
		'order_state', o.state, 'order_attempts', o.attempts,
		'order_claimed', o.work_owner IS NOT NULL, 'order_work_expires_at', o.work_expires_at,
		'order_available_at', o.available_at, 'order_updated_at', o.updated_at,
		'order_error_present', o.last_error IS NOT NULL,
		'ready_connections', connections.ready,
		'connection_leases', (SELECT jsonb_agg(jsonb_build_object(
			'slot', slot.connection_slot, 'state', slot.state, 'session_open', slot.session_open,
			'claim_relay_service_id', slot.relay_service_id, 'relay_service_id', lease.relay_service_id,
			'relay_lease_expires_at', lease.lease_expires_at, 'relay_draining', lease.draining,
			'claim_lease_revision', slot.relay_lease_revision, 'lease_revision', lease.relay_lease_revision,
			'claim_process_run_id', slot.relay_run_id, 'process_run_id', lease.relay_run_id)
			ORDER BY slot.connection_slot)
			FROM control.service_connection_slots slot
			LEFT JOIN control.relay_leases lease ON lease.relay_id=slot.relay_id
			WHERE slot.service_run_id=s.id),
		'active_ingresses', (SELECT count(*) FROM control.ingress_leases
			WHERE NOT draining AND lease_expires_at > now()),
		'endpoint_revision', r.endpoint_revision, 'trust_revision', r.trust_revision,
		'run_healthy', s.healthy, 'run_expires_at', s.publisher_expires_at,
		'run_certificate_expires_at', s.certificate_expires_at,
		'run_certificate_hostname', s.certificate_hostname,
		'run_certificate_domain_id', s.certificate_domain_id,
		'endpoint', (SELECT jsonb_build_object(
			'hostname', endpoint.hostname, 'domain_id', endpoint.domain_id,
			'public', endpoint.public, 'retired', endpoint.retired_at IS NOT NULL,
			'dns_state', endpoint.dns_state, 'dns_automation', endpoint.dns_automation,
			'dns_attempts', endpoint.dns_attempts, 'dns_error_present', endpoint.dns_last_error IS NOT NULL,
			'dns_revision', endpoint.dns_revision, 'dns_available_at', endpoint.dns_available_at,
			'dns_claimed', endpoint.dns_work_owner IS NOT NULL, 'dns_work_epoch', endpoint.dns_work_epoch,
			'dns_work_expires_at', endpoint.dns_work_expires_at,
			'pool_id', endpoint.ingress_pool_id, 'pool_state', pool.state,
			'ingresses', (SELECT jsonb_agg(jsonb_build_object(
				'https', ingress.https, 'draining', ingress.draining, 'expires_at', ingress.lease_expires_at))
				FROM control.ingress_leases ingress WHERE ingress.ingress_pool_id=endpoint.ingress_pool_id))
			FROM control.service_endpoints endpoint
			JOIN control.ingress_pools pool ON pool.id=endpoint.ingress_pool_id
			WHERE endpoint.service_id=r.id AND endpoint.hostname=r.certificate_hostname),
		'authorizations', (SELECT jsonb_agg(jsonb_build_object(
			'state', a.state, 'attempts', a.attempts, 'claimed', a.work_owner IS NOT NULL,
			'work_expires_at', a.work_expires_at, 'available_at', a.available_at,
			'updated_at', a.updated_at, 'error_present', a.last_error IS NOT NULL)
			ORDER BY a.id) FROM control.acme_authorizations a WHERE a.order_id = o.id)
	)::text
	FROM control.services r
	LEFT JOIN LATERAL (SELECT * FROM control.service_runs WHERE service_id = r.id ORDER BY run_number DESC LIMIT 1) s ON true
	LEFT JOIN LATERAL (SELECT * FROM control.acme_orders WHERE service_id = r.id AND service_run_id=s.id ORDER BY created_at DESC LIMIT 1) o ON true
	LEFT JOIN LATERAL (SELECT count(*) AS ready FROM control.service_connection_slots
		WHERE service_run_id = s.id AND state = 'ready' AND session_open) connections ON true
	WHERE r.certificate_hostname LIKE $1 LIMIT 1`, fmt.Sprintf("tnl-load-r%06d.%%", index)).Scan(&state)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	result := struct {
		CapturedAt time.Time       `json:"captured_at"`
		Index      int             `json:"index"`
		Service    json.RawMessage `json:"service,omitempty"`
	}{CapturedAt: time.Now(), Index: index}
	if err == nil {
		result.Service = json.RawMessage(state)
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join("/results", fmt.Sprintf("publisher-%06d-failure.json", index)), data, 0o644); err != nil {
		return fmt.Errorf("write publisher failure snapshot: %w", err)
	}
	return nil
}
