package tnldruntime

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// only explicit, non-secret response fields are logged. preserve the response
// bytes and closer for the real client; never log headers or challenge material.
func traceRuntimeCertificateHTTP(t *testing.T, client *http.Client, start time.Time) {
	base := client.Transport
	var observations atomic.Int64
	client.Transport = splitACMERoundTripFunc(func(request *http.Request) (*http.Response, error) {
		at := time.Now()
		response, err := base.RoundTrip(request)
		path := request.URL.Path
		if !strings.Contains(path, "/certificate-issuances") && !strings.HasSuffix(path, "/certificate-installed") &&
			!(strings.Contains(path, "/publish-runs/") && strings.HasSuffix(path, "/ready")) {
			return response, err
		}
		if observations.Add(1) > 4096 {
			return response, err
		}
		if err != nil {
			t.Logf("provision_http elapsed=%s path=%s failed=true", time.Since(start), path)
			return response, err
		}
		body, readErr := io.ReadAll(response.Body)
		response.Body = struct {
			io.Reader
			io.Closer
		}{bytes.NewReader(body), response.Body}
		var value struct {
			ID             string     `json:"id"`
			State          string     `json:"state"`
			RetryAt        *time.Time `json:"retry_at"`
			CertificatePEM *string    `json:"certificate_pem"`
		}
		_ = json.Unmarshal(body, &value)
		t.Logf("provision_http elapsed=%s duration=%s path=%s status=%d issuance=%s state=%s retry_at=%v material=%t read_error=%v",
			time.Since(start), time.Since(at), path, response.StatusCode, value.ID, value.State, value.RetryAt, value.CertificatePEM != nil, readErr)
		return response, err
	})
}

// sample at 250ms while activating, logging only state transitions. this is a
// test-only observer on the inspection connection, not a worker or metrics hook.
// attempts/epochs retain evidence of short claims between samples. the timestamps
// are database transition times; elapsed is the observation time.
func traceRuntimeCertificateState(t *testing.T, database *sql.DB, start time.Time) func() {
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		previous := make(map[string]string)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			sampleCtx, stop := context.WithTimeout(ctx, 2*time.Second)
			rows, err := database.QueryContext(sampleCtx, `SELECT o.id, jsonb_build_object(
				'hostname', r.canonical_hostname, 'state', o.state, 'created_at', o.created_at,
				'updated_at', o.updated_at, 'available_at', o.available_at, 'attempts', o.attempts,
				'claimed', o.work_owner IS NOT NULL, 'epoch', o.work_epoch,
				'installed_at', s.certificate_installed_at, 'session_state', s.state,
				'authorizations', (SELECT jsonb_agg(jsonb_build_object('state', a.state,
					'updated_at', a.updated_at, 'presented_at', a.presented_at) ORDER BY a.id)
					FROM control.acme_authorizations a WHERE a.order_id = o.id),
				'global_barrier_blocked', EXISTS (SELECT 1 FROM control.acme_authorizations a
					WHERE a.order_id = o.id AND a.state = 'presented') AND
					coalesce((SELECT min(i.routing_table_revision) FROM control.ingress_leases i
						WHERE NOT i.draining AND i.lease_expires_at > now()), -1) < clock.current_revision
			)::text, clock.current_revision,
			coalesce((SELECT min(i.routing_table_revision) FROM control.ingress_leases i
				WHERE NOT i.draining AND i.lease_expires_at > now()), -1),
			coalesce((SELECT max(e.routing_table_revision) FROM control.ingress_routing_table_events e
				WHERE e.public_url_id = o.public_url_id AND e.publish_run_number = o.publish_run_number
				AND e.event_kind IN ('challenge_upsert', 'challenge_tombstone')), 0)
			FROM control.acme_orders o JOIN control.public_urls r ON r.id = o.public_url_id
			JOIN control.publish_runs s ON s.id = o.publish_run_id
			CROSS JOIN control.ingress_routing_table_clock clock ORDER BY o.id`)
			if err == nil {
				for rows.Next() {
					var id, state string
					var head, applied, challenge int64
					if err = rows.Scan(&id, &state, &head, &applied, &challenge); err != nil {
						break
					}
					if previous[id] != state {
						t.Logf("provision_state elapsed=%s issuance=%s head=%d applied=%d challenge=%d state=%s", time.Since(start), id, head, applied, challenge, state)
						previous[id] = state
					}
				}
				if err == nil {
					err = rows.Err()
				}
				_ = rows.Close()
			}
			stop()
			if err != nil && ctx.Err() == nil {
				t.Errorf("provisioning timeline: %v", err)
				return
			}
		}
	}()
	stop := sync.OnceFunc(func() {
		cancel()
		<-done
	})
	t.Cleanup(stop)
	return stop
}
