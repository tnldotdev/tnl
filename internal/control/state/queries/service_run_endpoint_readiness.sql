-- name: ServiceRunPublicEndpointReady :one
-- the caller holds the service lock and validates the run's preparation facts.
-- use current DNS, relay, and ingress facts without authorizing visitor access.
SELECT EXISTS(
    SELECT 1 FROM control.service_endpoints endpoint
    JOIN control.ingress_pools pool ON pool.id=endpoint.ingress_pool_id
    WHERE endpoint.service_id=sqlc.arg(service_id)::text
      AND endpoint.hostname=sqlc.arg(hostname)::text AND endpoint.domain_id=sqlc.arg(domain_id)::text
      AND endpoint.ingress_pool_id=sqlc.arg(ingress_pool_id)::text
      AND endpoint.public AND endpoint.retired_at IS NULL
      AND (endpoint.service_run_id IS NULL OR endpoint.service_run_id=sqlc.arg(service_run_id)::text)
      AND (endpoint.dns_state='published' OR endpoint.dns_state='unmanaged' AND NOT endpoint.dns_automation)
      AND (pool.state IN('enabled','draining') OR pool.id=sqlc.arg(primary_ingress_pool_id)::text AND pool.state='disabled')
      AND EXISTS(SELECT 1 FROM control.service_connection_slots slot
        JOIN control.relay_leases relay ON relay.relay_id=slot.relay_id AND relay.relay_run_id=slot.relay_run_id
          AND relay.relay_lease_revision=slot.relay_lease_revision AND relay.relay_service_id=slot.relay_service_id
        WHERE slot.service_run_id=sqlc.arg(service_run_id)::text AND slot.state='ready' AND slot.session_open
          AND NOT relay.draining AND relay.lease_expires_at>sqlc.arg(now)::timestamptz)
      AND EXISTS(SELECT 1 FROM control.ingress_leases ingress WHERE ingress.ingress_pool_id=sqlc.arg(ingress_pool_id)::text
        AND (CASE WHEN sqlc.arg(protocol)::text='http' THEN ingress.https ELSE sqlc.arg(service_port)::integer=ANY(ingress.service_ports) END)
        AND NOT ingress.draining AND ingress.lease_expires_at>sqlc.arg(now)::timestamptz)
      AND NOT EXISTS(SELECT 1 FROM control.ingress_leases ingress WHERE ingress.ingress_pool_id=sqlc.arg(ingress_pool_id)::text
        AND NOT (CASE WHEN sqlc.arg(protocol)::text='http' THEN ingress.https ELSE sqlc.arg(service_port)::integer=ANY(ingress.service_ports) END)
        AND NOT ingress.draining AND ingress.lease_expires_at>sqlc.arg(now)::timestamptz)
) AS ready;

-- name: LockServiceRunFirstReadyEndpoint :one
-- guest first readiness retains DNS publication through the clock transition.
SELECT hostname FROM control.service_endpoints
WHERE service_id=sqlc.arg(service_id)::text AND hostname=sqlc.arg(hostname)::text
  AND domain_id=sqlc.arg(domain_id)::text AND ingress_pool_id=sqlc.arg(ingress_pool_id)::text
  AND public AND retired_at IS NULL
FOR SHARE;
