package tnldruntime

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Capture unfinished publisher state before the publisher group cancels its
// processes. Select only non-secret fields; the disposable database disappears
// when the separated workload stops.
func captureSeparatedPublisherFailure(database *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := database.QueryContext(ctx, `SELECT jsonb_build_object(
		'hostname', r.canonical_hostname, 'session_state', s.state,
		'session_created_at', s.created_at, 'session_ready_at', s.ready_at,
		'certificate_installed_at', s.certificate_installed_at,
		'order_state', o.state, 'order_attempts', o.attempts,
		'order_claimed', o.work_owner IS NOT NULL, 'order_work_expires_at', o.work_expires_at,
		'order_available_at', o.available_at, 'order_updated_at', o.updated_at,
		'order_error_present', o.last_error IS NOT NULL,
		'ready_connections', connections.ready,
		'authorizations', (SELECT jsonb_agg(jsonb_build_object(
			'state', a.state, 'attempts', a.attempts, 'claimed', a.work_owner IS NOT NULL,
			'work_expires_at', a.work_expires_at, 'available_at', a.available_at,
			'updated_at', a.updated_at, 'error_present', a.last_error IS NOT NULL)
			ORDER BY a.id) FROM control.acme_authorizations a WHERE a.order_id = o.id)
	)::text
	FROM control.routes r
	LEFT JOIN LATERAL (SELECT * FROM control.route_sessions WHERE route_id = r.id ORDER BY route_version DESC LIMIT 1) s ON true
	LEFT JOIN LATERAL (SELECT * FROM control.acme_orders WHERE route_id = r.id ORDER BY created_at DESC LIMIT 1) o ON true
	LEFT JOIN LATERAL (SELECT count(*) AS ready FROM control.route_session_connections
		WHERE route_session_id = s.id AND state = 'ready') connections ON true
	WHERE r.canonical_hostname LIKE 'tnlbench-r%' AND
		(s.id IS NULL OR s.state <> 'ready' OR s.certificate_installed_at IS NULL
		 OR o.state IS DISTINCT FROM 'installed' OR connections.ready <> 2)
	ORDER BY r.canonical_hostname LIMIT 1501`)
	if err != nil {
		return err
	}
	var unfinished []json.RawMessage
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			_ = rows.Close()
			return err
		}
		unfinished = append(unfinished, json.RawMessage(value))
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return err
	}
	const limit = 1500
	result := struct {
		CapturedAt time.Time         `json:"captured_at"`
		Truncated  bool              `json:"truncated"`
		Unfinished []json.RawMessage `json:"unfinished"`
	}{time.Now(), len(unfinished) > limit, unfinished[:min(len(unfinished), limit)]}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join("/results", "publisher-failure.json"), data, 0o644); err != nil {
		return fmt.Errorf("write publisher failure snapshot: %w", err)
	}
	return nil
}
