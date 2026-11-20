-- name: ClaimServiceEndpointDNSWork :one
WITH candidate AS (
    SELECT work.hostname FROM control.service_endpoints work
    WHERE work.dns_state IN ('pending','removing') AND work.dns_available_at<=sqlc.arg(now)
      AND (work.dns_work_owner IS NULL OR work.dns_work_expires_at<=sqlc.arg(now))
      AND (NOT work.public OR work.dns_state='removing' OR EXISTS (
          SELECT 1 FROM control.services service
          JOIN control.service_runs run ON run.service_id=service.id
           WHERE service.id=work.service_id AND service.public AND service.enabled AND service.deleted_at IS NULL
              AND service.domain_id=work.domain_id
              AND run.certificate_hostname=service.certificate_hostname AND run.certificate_domain_id=work.domain_id
              AND (work.service_run_id IS NULL AND service.certificate_hostname=work.hostname
                OR work.service_run_id=run.id AND run.run_hostname=work.hostname AND run.run_alias_parent=service.run_alias_parent)
              AND EXISTS(SELECT 1 FROM control.service_endpoints canonical
                WHERE canonical.service_id=service.id AND canonical.hostname=service.certificate_hostname
                  AND canonical.domain_id=service.domain_id AND canonical.retired_at IS NULL AND canonical.public)
             AND (run.state='ready' OR run.state='starting' AND run.ready_at IS NULL
               AND run.guest_id=service.guest_id
               AND EXISTS(SELECT 1 FROM control.guest_trials guest
                 WHERE guest.id=run.guest_id AND guest.active_service_run_id=run.id
                   AND guest.ended_at IS NULL AND guest.expires_at>sqlc.arg(now)
                   AND guest.used_ready_ns<1200000000000)
               AND (SELECT count(*) FROM control.service_connection_slots slot
                 JOIN control.relay_leases relay ON relay.relay_id=slot.relay_id AND relay.relay_run_id=slot.relay_run_id
                   AND relay.relay_lease_revision=slot.relay_lease_revision AND relay.relay_service_id=slot.relay_service_id
                 WHERE slot.service_run_id=run.id AND slot.service_id=run.service_id AND slot.run_number=run.run_number
                   AND slot.state='ready' AND slot.session_open
                   AND NOT relay.draining AND relay.lease_expires_at>sqlc.arg(now))=2)
             AND run.healthy AND run.closed_at IS NULL
            AND run.publisher_expires_at>sqlc.arg(now) AND run.certificate_expires_at>sqlc.arg(now)
            AND EXISTS(SELECT 1 FROM control.service_connection_slots slot
              JOIN control.relay_leases relay ON relay.relay_id=slot.relay_id AND relay.relay_run_id=slot.relay_run_id
                AND relay.relay_lease_revision=slot.relay_lease_revision AND relay.relay_service_id=slot.relay_service_id
              WHERE slot.service_run_id=run.id AND slot.state='ready' AND slot.session_open
                AND NOT relay.draining AND relay.lease_expires_at>sqlc.arg(now))
            AND EXISTS (SELECT 1 FROM control.ingress_leases ingress WHERE ingress.ingress_pool_id=work.ingress_pool_id
              AND (CASE WHEN service.protocol='http' THEN ingress.https ELSE service.service_port <@ ingress.service_port_ranges END)
              AND NOT ingress.draining AND ingress.lease_expires_at>sqlc.arg(now))
            AND NOT EXISTS (SELECT 1 FROM control.ingress_leases ingress WHERE ingress.ingress_pool_id=work.ingress_pool_id
              AND NOT (CASE WHEN service.protocol='http' THEN ingress.https ELSE service.service_port <@ ingress.service_port_ranges END)
              AND NOT ingress.draining AND ingress.lease_expires_at>sqlc.arg(now))
      ))
    ORDER BY work.dns_available_at,work.hostname FOR UPDATE SKIP LOCKED LIMIT 1
)
UPDATE control.service_endpoints endpoint
SET dns_work_owner=sqlc.arg(worker),dns_work_epoch=endpoint.dns_work_epoch+1,
    dns_work_expires_at=sqlc.arg(expires_at),dns_attempts=endpoint.dns_attempts+1
FROM candidate WHERE endpoint.hostname=candidate.hostname RETURNING endpoint.*;

-- name: SaveServiceEndpointDNSWork :one
UPDATE control.service_endpoints
SET dns_state=sqlc.arg(state),dns_revision=dns_revision+1,dns_available_at=sqlc.narg(available_at),
    dns_last_error=sqlc.narg(last_error),dns_work_owner=NULL,dns_work_expires_at=NULL
WHERE hostname=sqlc.arg(hostname) AND service_id=sqlc.arg(service_id) AND dns_revision=sqlc.arg(revision)
    AND dns_work_owner=sqlc.arg(worker) AND dns_work_epoch=sqlc.arg(epoch) AND dns_work_expires_at>sqlc.arg(now)
RETURNING *;

-- name: ValidateServiceEndpointDNSWork :one
-- use the same publication candidate as claim, including first-ready guests.
SELECT EXISTS(
    SELECT 1 FROM control.service_endpoints work
    WHERE work.hostname=sqlc.arg(hostname)::text AND work.service_id=sqlc.arg(service_id)::text
      AND work.dns_revision=sqlc.arg(revision)::bigint AND work.dns_work_owner=sqlc.arg(worker)::text
      AND work.dns_work_epoch=sqlc.arg(epoch)::bigint AND work.dns_work_expires_at>sqlc.arg(now)::timestamptz
      AND (NOT work.public OR work.dns_state='removing' OR EXISTS (
          SELECT 1 FROM control.services service
          JOIN control.service_runs run ON run.service_id=service.id
           WHERE service.id=work.service_id AND service.public AND service.enabled AND service.deleted_at IS NULL
              AND service.domain_id=work.domain_id
              AND run.certificate_hostname=service.certificate_hostname AND run.certificate_domain_id=work.domain_id
              AND (work.service_run_id IS NULL AND service.certificate_hostname=work.hostname
                OR work.service_run_id=run.id AND run.run_hostname=work.hostname AND run.run_alias_parent=service.run_alias_parent)
              AND EXISTS(SELECT 1 FROM control.service_endpoints canonical
                WHERE canonical.service_id=service.id AND canonical.hostname=service.certificate_hostname
                  AND canonical.domain_id=service.domain_id AND canonical.retired_at IS NULL AND canonical.public)
             AND (run.state='ready' OR run.state='starting' AND run.ready_at IS NULL
               AND run.guest_id=service.guest_id
               AND EXISTS(SELECT 1 FROM control.guest_trials guest
                 WHERE guest.id=run.guest_id AND guest.active_service_run_id=run.id
                   AND guest.ended_at IS NULL AND guest.expires_at>sqlc.arg(now)
                   AND guest.used_ready_ns<1200000000000)
               AND (SELECT count(*) FROM control.service_connection_slots slot
                 JOIN control.relay_leases relay ON relay.relay_id=slot.relay_id AND relay.relay_run_id=slot.relay_run_id
                   AND relay.relay_lease_revision=slot.relay_lease_revision AND relay.relay_service_id=slot.relay_service_id
                 WHERE slot.service_run_id=run.id AND slot.service_id=run.service_id AND slot.run_number=run.run_number
                   AND slot.state='ready' AND slot.session_open
                   AND NOT relay.draining AND relay.lease_expires_at>sqlc.arg(now))=2)
             AND run.healthy AND run.closed_at IS NULL
             AND run.publisher_expires_at>sqlc.arg(now) AND run.certificate_expires_at>sqlc.arg(now)
             AND EXISTS(SELECT 1 FROM control.service_connection_slots slot
               JOIN control.relay_leases relay ON relay.relay_id=slot.relay_id AND relay.relay_run_id=slot.relay_run_id
                 AND relay.relay_lease_revision=slot.relay_lease_revision AND relay.relay_service_id=slot.relay_service_id
               WHERE slot.service_run_id=run.id AND slot.state='ready' AND slot.session_open
                 AND NOT relay.draining AND relay.lease_expires_at>sqlc.arg(now))
             AND EXISTS (SELECT 1 FROM control.ingress_leases ingress WHERE ingress.ingress_pool_id=work.ingress_pool_id
               AND (CASE WHEN service.protocol='http' THEN ingress.https ELSE service.service_port <@ ingress.service_port_ranges END)
               AND NOT ingress.draining AND ingress.lease_expires_at>sqlc.arg(now))
             AND NOT EXISTS (SELECT 1 FROM control.ingress_leases ingress WHERE ingress.ingress_pool_id=work.ingress_pool_id
               AND NOT (CASE WHEN service.protocol='http' THEN ingress.https ELSE service.service_port <@ ingress.service_port_ranges END)
               AND NOT ingress.draining AND ingress.lease_expires_at>sqlc.arg(now))
      ))
) AS valid;
