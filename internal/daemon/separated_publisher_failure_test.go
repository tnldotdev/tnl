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
		'active_ingresses', (SELECT count(*) FROM control.ingress_leases
			WHERE NOT draining AND lease_expires_at > now()),
		'endpoint_revision', r.endpoint_revision, 'trust_revision', r.trust_revision,
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
	if err := os.WriteFile(filepath.Join("/results", "publisher-failure.json"), data, 0o644); err != nil {
		return fmt.Errorf("write publisher failure snapshot: %w", err)
	}
	return nil
}
