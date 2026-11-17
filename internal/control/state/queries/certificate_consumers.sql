-- name: LockServiceCertificateOrdersForConsumer :many
-- run closure holds its parent first. lock shared orders in stable order before
-- taking a fresh consumer snapshot, so concurrent final closes cannot miss both.
SELECT issuance.id
FROM control.acme_orders issuance
JOIN control.service_runs origin ON origin.id=issuance.service_run_id
JOIN control.service_runs departing ON departing.id=sqlc.arg(service_run_id)
WHERE origin.publisher_identity_id=departing.publisher_identity_id
    AND origin.team_id IS NOT DISTINCT FROM departing.team_id
    AND origin.guest_id IS NOT DISTINCT FROM departing.guest_id
    AND issuance.certificate_cache_key=departing.certificate_cache_key
    AND issuance.certificate_scope=departing.certificate_scope
    AND issuance.certificate_identifiers=departing.certificate_identifiers
    AND issuance.certificate_domain_id IS NOT DISTINCT FROM departing.certificate_domain_id
    AND issuance.state IN ('pending','authorizing','ready_to_finalize','finalizing')
ORDER BY issuance.id
FOR UPDATE OF issuance;

-- name: RetireUnusedServiceCertificateOrder :exec
-- a captured, current plan is interest even before its sibling submits a CSR.
-- publisher_service_permission remains the authority for service/grant/owner
-- policy. serving_until is authority; shorter publisher liveness is not expiry.
WITH retired AS (
    UPDATE control.acme_orders issuance
    SET state='canceled',order_revision=order_revision+1,
        finalization_possible=issuance.finalization_possible OR issuance.state IN ('ready_to_finalize','finalizing'),
        available_at=sqlc.arg(now),retry_not_before=NULL,
        last_error='no authorized certificate consumer',updated_at=sqlc.arg(now)
    FROM control.service_runs origin
    WHERE issuance.id=sqlc.arg(issuance_id) AND origin.id=issuance.service_run_id
        AND issuance.state IN ('pending','authorizing','ready_to_finalize','finalizing')
        AND NOT EXISTS (
            SELECT 1 FROM control.service_runs consumer
            JOIN control.publisher_grants grant_record ON grant_record.id=consumer.publisher_grant_id
                AND grant_record.publisher_identity_id=consumer.publisher_identity_id
            JOIN control.publisher_identity_keys signing ON signing.id=consumer.publisher_key_id
                AND signing.publisher_identity_id=consumer.publisher_identity_id
            JOIN control.domains domain ON domain.id=consumer.certificate_domain_id
                AND domain.state='ready' AND domain.released_at IS NULL
                AND (domain.kind='managed' OR domain.team_id=consumer.team_id)
            WHERE consumer.publisher_identity_id=origin.publisher_identity_id
                AND consumer.team_id IS NOT DISTINCT FROM origin.team_id
                AND consumer.guest_id IS NOT DISTINCT FROM origin.guest_id
                AND consumer.certificate_cache_key=issuance.certificate_cache_key
                AND consumer.certificate_scope=issuance.certificate_scope
                AND consumer.certificate_identifiers=issuance.certificate_identifiers
                AND consumer.certificate_domain_id IS NOT DISTINCT FROM issuance.certificate_domain_id
                AND consumer.closed_at IS NULL AND consumer.serving_until>sqlc.arg(now)
                AND (consumer.state IN ('starting','ready') OR consumer.state='prepared' AND consumer.preparation_expires_at>sqlc.arg(now))
                AND (grant_record.kind='service' OR signing.retired_at IS NULL)
                AND EXISTS (SELECT 1 FROM control.publisher_service_permission(
                    consumer.publisher_identity_id,consumer.publisher_grant_id,consumer.service_id,sqlc.arg(now)))
        )
    RETURNING issuance.id
)
UPDATE control.acme_authorizations authz
SET state=CASE WHEN challenge_type='dns-01'
        AND (state IN ('presenting','presented','validating','valid','cleaning') OR presented_at IS NOT NULL)
        THEN 'cleaning' ELSE 'canceled' END,
    authorization_revision=authorization_revision+1,available_at=sqlc.arg(now),updated_at=sqlc.arg(now)
WHERE authz.order_id IN (SELECT id FROM retired) AND authz.state NOT IN ('complete','canceled');
