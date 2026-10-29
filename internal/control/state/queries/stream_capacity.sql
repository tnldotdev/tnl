-- name: FindStreamCapacityAllocation :one
SELECT * FROM control.stream_capacity_allocations
WHERE resource_kind=sqlc.arg(resource_kind) AND resource_id=sqlc.arg(resource_id) AND run_id=sqlc.arg(run_id)
    AND ingress_id=sqlc.arg(ingress_id) AND ingress_run_id=sqlc.arg(ingress_run_id) AND ingress_lease_revision=sqlc.arg(ingress_lease_revision)
    AND request_id=sqlc.arg(request_id) FOR UPDATE;

-- name: SumStreamCapacityAllocations :one
SELECT COALESCE(sum(capacity),0)::bigint FROM control.stream_capacity_allocations
WHERE resource_kind=sqlc.arg(resource_kind) AND resource_id=sqlc.arg(resource_id) AND run_id=sqlc.arg(run_id) AND valid_until>sqlc.arg(now);

-- name: CountEligibleIngressesByPool :one
SELECT count(*) FROM control.ingress_leases
WHERE ingress_pool_id=sqlc.arg(ingress_pool_id) AND lease_expires_at>sqlc.arg(now)
    AND NOT draining AND protocol_version=sqlc.arg(protocol_version) AND connection_capacity>0
    AND (sqlc.arg(resource_kind)::text<>'public_url' OR NOT connector_only);

-- name: SumOwnedStreamCapacityAllocations :one
SELECT COALESCE(sum(capacity),0)::bigint FROM control.stream_capacity_allocations
WHERE resource_kind=sqlc.arg(resource_kind) AND resource_id=sqlc.arg(resource_id) AND run_id=sqlc.arg(run_id)
    AND ingress_id=sqlc.arg(ingress_id) AND ingress_run_id=sqlc.arg(ingress_run_id)
    AND ingress_lease_revision=sqlc.arg(ingress_lease_revision) AND valid_until>sqlc.arg(now);

-- name: CountStreamCapacityAllocations :one
SELECT count(*) FROM control.stream_capacity_allocations
WHERE resource_kind=sqlc.arg(resource_kind) AND resource_id=sqlc.arg(resource_id) AND valid_until>sqlc.arg(now);

-- name: CreateStreamCapacityAllocation :one
INSERT INTO control.stream_capacity_allocations(id,resource_kind,resource_id,run_id,run_number,ingress_id,ingress_run_id,ingress_lease_revision,request_id,capacity,proof_key_ciphertext,proof_key_storage_key_id,issued_at,renewed_at,valid_until)
VALUES(sqlc.arg(id),sqlc.arg(resource_kind),sqlc.arg(resource_id),sqlc.arg(run_id),sqlc.arg(run_number),sqlc.arg(ingress_id),sqlc.arg(ingress_run_id),sqlc.arg(ingress_lease_revision),sqlc.arg(request_id),sqlc.arg(capacity),sqlc.arg(proof_key_ciphertext),sqlc.arg(proof_key_storage_key_id),sqlc.arg(now),sqlc.arg(now),sqlc.arg(valid_until)) RETURNING *;

-- name: RenewStreamCapacityAllocation :one
UPDATE control.stream_capacity_allocations SET renewed_at=sqlc.arg(now),valid_until=sqlc.arg(valid_until)
WHERE id=sqlc.arg(id) AND retired_at IS NULL AND valid_until>sqlc.arg(now) AND renewed_at<=sqlc.arg(now) RETURNING *;

-- name: RetireStreamCapacityAllocation :execrows
UPDATE control.stream_capacity_allocations SET retired_at=COALESCE(retired_at,sqlc.arg(now))
WHERE id=sqlc.arg(id) AND ingress_id=sqlc.arg(ingress_id) AND ingress_run_id=sqlc.arg(ingress_run_id) AND ingress_lease_revision=sqlc.arg(ingress_lease_revision);

-- name: ReadStreamCapacityAllocations :many
SELECT * FROM control.stream_capacity_allocations
WHERE resource_kind=sqlc.arg(resource_kind) AND resource_id=sqlc.arg(resource_id) AND valid_until>sqlc.arg(now)
ORDER BY id LIMIT 2049;

-- name: ObservePublisherStreamAllocation :execrows
UPDATE control.stream_capacity_allocations SET publisher_observed_until=LEAST(sqlc.arg(valid_until),valid_until)
WHERE resource_kind=sqlc.arg(resource_kind) AND resource_id=sqlc.arg(resource_id)
    AND run_id=sqlc.arg(run_id) AND run_number=sqlc.arg(run_number)
    AND id=sqlc.arg(id) AND retired_at IS NULL AND valid_until>sqlc.arg(now)
    AND sqlc.arg(valid_until)::timestamptz>sqlc.arg(now);

-- name: PublishRunServingPrepared :one
-- routing installation and per-URL preparation are independent observations.
WITH selected AS (
    SELECT run.id, run.publish_run_number, url.id AS public_url_id, url.ingress_pool_id,
        (SELECT max(event.id) FROM control.ingress_routing_table_events event
         WHERE event.public_url_id=url.id AND event.publish_run_number=run.publish_run_number) AS revision
    FROM control.publish_runs run JOIN control.public_urls url ON url.id=run.public_url_id
    WHERE run.id=sqlc.arg(run_id) AND run.publish_run_number=sqlc.arg(run_number)
        AND run.state IN ('starting','ready') AND run.closed_at IS NULL AND run.publisher_expires_at>sqlc.arg(now)
        AND run.certificate_not_after>sqlc.arg(now) AND url.lifecycle_state='enabled'
        AND (url.expires_at IS NULL OR url.expires_at>sqlc.arg(now))
), receivers AS (
    SELECT ingress.*, selected.id AS run_id, selected.publish_run_number,
        selected.public_url_id, selected.revision
    FROM selected JOIN control.ingress_leases ingress ON ingress.ingress_pool_id=selected.ingress_pool_id
    WHERE ingress.lease_expires_at>sqlc.arg(now) AND NOT ingress.draining AND NOT ingress.connector_only
        AND ingress.protocol_version=sqlc.arg(protocol_version) AND ingress.connection_capacity>0
)
SELECT CASE WHEN EXISTS(SELECT 1 FROM receivers)
    AND NOT EXISTS (
        SELECT 1 FROM receivers receiver
        WHERE receiver.revision IS NULL OR receiver.routing_table_revision<receiver.revision
            OR NOT EXISTS (
                SELECT 1 FROM control.stream_capacity_allocations allocation
                WHERE allocation.resource_kind='public_url' AND allocation.resource_id=receiver.public_url_id
                    AND allocation.run_id=receiver.run_id AND allocation.run_number=receiver.publish_run_number
                    AND allocation.ingress_id=receiver.ingress_id AND allocation.ingress_run_id=receiver.ingress_run_id
                    AND allocation.ingress_lease_revision=receiver.ingress_lease_revision
                    AND allocation.retired_at IS NULL AND allocation.valid_until>sqlc.arg(now)
                    AND allocation.publisher_observed_until>sqlc.arg(now)
                    AND allocation.ingress_observed_until>sqlc.arg(now)
            )
    ) THEN true ELSE false END AS prepared;

-- name: ObserveIngressStreamAllocation :execrows
UPDATE control.stream_capacity_allocations allocation
SET ingress_observed_until=LEAST(sqlc.arg(valid_until),allocation.valid_until)
WHERE allocation.resource_kind=sqlc.arg(resource_kind) AND allocation.resource_id=sqlc.arg(resource_id)
    AND allocation.resource_kind='public_url'
    AND allocation.id=sqlc.arg(id) AND allocation.run_id=sqlc.arg(run_id) AND allocation.run_number=sqlc.arg(run_number)
    AND allocation.ingress_id=sqlc.arg(ingress_id) AND allocation.ingress_run_id=sqlc.arg(ingress_run_id)
    AND allocation.ingress_lease_revision=sqlc.arg(ingress_lease_revision)
    AND allocation.retired_at IS NULL AND allocation.valid_until>sqlc.arg(now)
    AND allocation.publisher_observed_until>sqlc.arg(now)
    AND sqlc.arg(valid_until)::timestamptz>sqlc.arg(now)
    AND EXISTS (
        SELECT 1 FROM control.publish_runs run JOIN control.public_urls url ON url.id=run.public_url_id
        WHERE run.id=allocation.run_id AND run.public_url_id=allocation.resource_id
            AND run.publish_run_number=allocation.run_number AND run.state IN ('starting','ready')
            AND run.closed_at IS NULL AND run.publisher_expires_at>sqlc.arg(now)
            AND url.lifecycle_state='enabled' AND (url.expires_at IS NULL OR url.expires_at>sqlc.arg(now))
    );

-- name: ReadPublishRunPreparationRouting :one
SELECT event.id, event.entry_revision FROM control.ingress_routing_table_events event
WHERE event.id=(SELECT max(history.id) FROM control.ingress_routing_table_events history
    WHERE history.public_url_id=sqlc.arg(public_url_id) AND history.publish_run_number=sqlc.arg(run_number))
    AND event.event_kind='public_url_upsert' AND event.public_url_expires_at>sqlc.arg(now);
