package state

import (
	"context"
	"time"
)

// quarantine is bounded by real authority, not merely elapsed wall time. a late
// issuance or unfinished DNS cleanup keeps the old port reserved.
func (d *Database) ReleaseServicePorts(ctx context.Context, now time.Time) (int64, error) {
	result, err := d.pool.Exec(ctx, `WITH candidate AS (
	    SELECT claim.id FROM control.service_port_claims claim
	    JOIN control.services service ON service.id=claim.service_id AND service.deleted_at IS NOT NULL
	    WHERE claim.state='quarantined' AND claim.reusable_after<=$1
	      AND NOT EXISTS(SELECT 1 FROM control.service_endpoints endpoint WHERE endpoint.service_id=service.id AND endpoint.dns_state<>'removed')
	      AND NOT EXISTS(SELECT 1 FROM control.service_runs run WHERE run.service_id=service.id AND(run.certificate_expires_at>$1 OR run.closed_at IS NULL AND run.publisher_expires_at>$1))
	      AND NOT EXISTS(SELECT 1 FROM control.acme_orders issuance WHERE issuance.service_id=service.id
	        AND(issuance.not_after>$1 OR issuance.state NOT IN('waiting_for_install','installed','failed','canceled') OR issuance.finalization_possible AND issuance.not_after IS NULL
	          OR EXISTS(SELECT 1 FROM control.acme_authorizations auth WHERE auth.order_id=issuance.id AND(auth.state IN('presenting','presented','validating','valid','cleaning') OR auth.presented_at IS NOT NULL AND auth.cleanup_completed_at IS NULL))))
	    ORDER BY claim.id FOR UPDATE OF claim SKIP LOCKED LIMIT 1000
	) UPDATE control.service_port_claims claim SET state='released' FROM candidate WHERE claim.id=candidate.id`, now)
	return result.RowsAffected(), err
}
