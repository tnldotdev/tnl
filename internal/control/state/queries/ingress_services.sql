-- name: ListIngressServiceRuns :many
-- routing is read from one snapshot, never changed by a visitor connection.
SELECT sqlc.embed(service),sqlc.embed(run),
    LEAST(run.serving_until,run.certificate_expires_at,permission.expires_at)::timestamptz AS valid_until,
    policy.revision AS visitor_policy_revision,recovery.id AS recovery_episode_id,
    COALESCE((SELECT alias.hostname FROM control.service_endpoints alias
      WHERE alias.service_run_id=run.id AND alias.service_id=service.id AND alias.hostname=run.run_hostname
        AND run.run_alias_parent=service.run_alias_parent AND alias.domain_id=service.domain_id
        AND alias.ingress_pool_id=service.ingress_pool_id AND alias.public AND alias.retired_at IS NULL
        AND (alias.dns_state='published' OR alias.dns_state='unmanaged' AND NOT alias.dns_automation)),'')::text AS alias_hostname
FROM control.services service
JOIN control.service_runs run ON run.service_id=service.id
JOIN control.visitor_policies policy ON policy.resource_id=service.id
LEFT JOIN control.service_recovery_episodes recovery ON recovery.service_run_id=run.id AND recovery.state='open'
JOIN LATERAL control.publisher_service_permission(run.publisher_identity_id,run.publisher_grant_id,service.id,sqlc.arg(now)) permission ON true
JOIN control.publisher_grants grant_record ON grant_record.id=run.publisher_grant_id
JOIN control.publisher_identity_keys signing ON signing.id=run.publisher_key_id
    AND signing.publisher_identity_id=run.publisher_identity_id
    AND (grant_record.kind='service' OR signing.retired_at IS NULL)
WHERE service.ingress_pool_id=sqlc.arg(ingress_pool_id) AND service.public AND service.enabled
    AND service.deleted_at IS NULL AND (service.expires_at IS NULL OR service.expires_at>sqlc.arg(now))
    AND run.state='ready' AND run.healthy AND run.closed_at IS NULL
    AND run.serving_until>sqlc.arg(now) AND run.certificate_expires_at>sqlc.arg(now)
    AND run.certificate_hostname=service.certificate_hostname
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
