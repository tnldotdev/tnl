-- name: ListLiveIngressRuns :many
-- heartbeat deadlines and signing input always come from the current snapshot.
SELECT run.id,run.run_token_digest,LEAST(run.serving_until,run.certificate_expires_at,service.expires_at)::timestamptz AS valid_until,
    recovery.id AS recovery_episode_id
FROM control.service_runs run JOIN control.services service ON service.id=run.service_id
LEFT JOIN control.service_recovery_episodes recovery ON recovery.service_run_id=run.id AND recovery.state='open'
WHERE service.ingress_pool_id=sqlc.arg(ingress_pool_id) AND service.public AND service.enabled AND service.deleted_at IS NULL
    AND (service.expires_at IS NULL OR service.expires_at>sqlc.arg(now)) AND run.state='ready' AND run.healthy AND run.closed_at IS NULL
    AND run.serving_until>sqlc.arg(now) AND run.certificate_expires_at>sqlc.arg(now)
ORDER BY service.id,run.run_number;

-- name: ListIngressServiceRuns :many
-- only recompute permission and DNS for runs with changed inputs. membership
-- eligibility may expire without changing a row or the grant's own deadline.
SELECT service.id AS service_id,run.id AS run_id,run.run_number,service.protocol,service.certificate_hostname,
    service.service_port,service.endpoint_revision,run.traffic_limits,policy.revision AS visitor_policy_revision,
    permission.expires_at::timestamptz AS permission_until,
    (SELECT min(valid_until) FROM control.company_eligibility WHERE eligible AND valid_until>sqlc.arg(now))::timestamptz AS recheck_at,
    ARRAY[hashtext(service.id)&255,hashtext(run.id)&255,hashtext(run.publisher_identity_id)&255,
        hashtext(run.publisher_grant_id)&255,hashtext(run.publisher_key_id)&255,hashtext(COALESCE(service.guest_id,''))&255,
        hashtext(service.certificate_hostname)&255,hashtext(run.run_hostname)&255,hashtext(run.run_alias_parent)&255]::integer[] AS buckets,
    CASE WHEN alias.dns_until IS NOT NULL THEN alias.hostname ELSE '' END::text AS alias_hostname,
    NULLIF(alias.dns_until,'infinity'::timestamptz)::timestamptz AS alias_dns_until
FROM control.services service
JOIN control.service_runs run ON run.service_id=service.id
LEFT JOIN LATERAL (
    SELECT endpoint.hostname,control.publisher_alias_dns_until(endpoint,sqlc.arg(now)::timestamptz) AS dns_until
    FROM control.service_endpoints endpoint
    WHERE endpoint.service_run_id=run.id AND endpoint.service_id=service.id AND endpoint.hostname=run.run_hostname
      AND run.run_alias_parent=service.run_alias_parent AND endpoint.domain_id=service.domain_id
      AND endpoint.ingress_pool_id=service.ingress_pool_id AND endpoint.public AND endpoint.retired_at IS NULL
) alias ON true
JOIN control.visitor_policies policy ON policy.resource_id=service.id
JOIN LATERAL control.publisher_service_permission(run.publisher_identity_id,run.publisher_grant_id,service.id,sqlc.arg(now)) permission ON true
JOIN control.publisher_grants grant_record ON grant_record.id=run.publisher_grant_id
JOIN control.publisher_identity_keys signing ON signing.id=run.publisher_key_id
    AND signing.publisher_identity_id=run.publisher_identity_id
    AND (grant_record.kind='service' OR signing.retired_at IS NULL)
WHERE run.id=ANY(sqlc.arg(run_ids)::text[]) AND run.certificate_hostname=service.certificate_hostname
    AND run.certificate_domain_id IS NOT DISTINCT FROM service.domain_id
    AND EXISTS(SELECT 1 FROM control.service_endpoints endpoint
        WHERE endpoint.service_id=service.id AND endpoint.hostname=service.certificate_hostname
            AND endpoint.domain_id=service.domain_id AND endpoint.retired_at IS NULL)
ORDER BY service.id,run.run_number;

-- name: ListIngressServiceRelays :many
SELECT slot.service_run_id,slot.publisher_connection_id,slot.connection_slot,slot.connection_assignment_revision,
    slot.relay_service_id,lease.relay_id,lease.relay_run_id,lease.relay_lease_revision,
    lease.internal_relay_address,lease.lease_expires_at,lease.serving_until,service.tls_server_name
FROM control.service_connection_slots slot
JOIN control.relay_services service ON service.relay_service_id=slot.relay_service_id
JOIN control.relay_leases lease ON lease.relay_id=slot.relay_id
    AND lease.relay_run_id=slot.relay_run_id AND lease.relay_lease_revision=slot.relay_lease_revision
    AND lease.relay_service_id=slot.relay_service_id
WHERE slot.service_run_id=ANY(sqlc.arg(service_run_ids)::text[]) AND slot.state='ready' AND slot.session_open
    AND lease.serving_until>sqlc.arg(now) AND NOT lease.draining
ORDER BY slot.service_run_id,slot.connection_slot;
