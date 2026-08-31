-- name: AdvanceRouteLifecycleSequence :one
UPDATE routes
SET lifecycle_sequence = lifecycle_sequence + 1
WHERE id = sqlc.arg(route_id)
RETURNING lifecycle_sequence;

-- name: CountRouteLifecycleTransition :one
SELECT COUNT(*)
FROM route_lifecycle_events
WHERE route_id = sqlc.arg(route_id)
    AND generation = sqlc.arg(generation)
    AND transition = sqlc.arg(transition);

-- name: InsertRouteLifecycleEvent :one
INSERT INTO route_lifecycle_events (
    event_id,
    route_id,
    generation,
    sequence,
    occurred_at_ns,
    transition
) VALUES (
    sqlc.arg(event_id),
    sqlc.arg(route_id),
    sqlc.arg(generation),
    sqlc.arg(sequence),
    sqlc.arg(occurred_at_ns),
    sqlc.arg(transition)
)
RETURNING id;

-- name: UpsertRouteExportOutbox :exec
INSERT INTO route_export_outbox (
    source_kind,
    source_id,
    source_revision,
    created_at_ns
) VALUES (
    sqlc.arg(source_kind),
    sqlc.arg(source_id),
    sqlc.arg(source_revision),
    sqlc.arg(created_at_ns)
)
ON CONFLICT (source_kind, source_id) DO UPDATE SET
    source_revision = excluded.source_revision,
    created_at_ns = excluded.created_at_ns
WHERE excluded.source_revision > route_export_outbox.source_revision;

-- name: GetNextLifecycleExport :one
SELECT
    sqlc.embed(route_lifecycle_events),
    route_export_outbox.source_revision,
    route_export_outbox.created_at_ns
FROM route_export_outbox
JOIN route_lifecycle_events ON route_lifecycle_events.id = route_export_outbox.source_id
WHERE route_export_outbox.source_kind = 'lifecycle_event'
ORDER BY route_export_outbox.created_at_ns, route_export_outbox.source_id
LIMIT 1;

-- name: GetNextUsageExport :one
SELECT
    sqlc.embed(route_usage_buckets),
    route_export_outbox.source_revision,
    route_export_outbox.created_at_ns
FROM route_export_outbox
JOIN route_usage_buckets ON route_usage_buckets.id = route_export_outbox.source_id
WHERE route_export_outbox.source_kind = 'usage_snapshot'
ORDER BY route_export_outbox.created_at_ns, route_export_outbox.source_id
LIMIT 1;

-- name: DeleteRouteExportOutboxRevision :execrows
DELETE FROM route_export_outbox
WHERE source_kind = sqlc.arg(source_kind)
    AND source_id = sqlc.arg(source_id)
    AND source_revision = sqlc.arg(source_revision);

-- name: CountRouteExportOutboxByKind :one
SELECT COUNT(*)
FROM route_export_outbox
WHERE source_kind = sqlc.arg(source_kind);

-- name: GetOldestRouteExportOutboxTime :one
SELECT created_at_ns
FROM route_export_outbox
ORDER BY created_at_ns
LIMIT 1;

-- name: UpsertRouteUsageBucket :one
INSERT INTO route_usage_buckets (
    route_id,
    generation,
    resolution,
    bucket_start_ns,
    revision,
    source_through_ns,
    connections_opened,
    connection_ns,
    ingress_bytes,
    egress_bytes,
    complete
) VALUES (
    sqlc.arg(route_id),
    sqlc.arg(generation),
    sqlc.arg(resolution),
    sqlc.arg(bucket_start_ns),
    sqlc.arg(revision),
    sqlc.arg(source_through_ns),
    sqlc.arg(connections_opened),
    sqlc.arg(connection_ns),
    sqlc.arg(ingress_bytes),
    sqlc.arg(egress_bytes),
    sqlc.arg(complete)
)
ON CONFLICT (route_id, generation, resolution, bucket_start_ns) DO UPDATE SET
    revision = excluded.revision,
    source_through_ns = excluded.source_through_ns,
    connections_opened = excluded.connections_opened,
    connection_ns = excluded.connection_ns,
    ingress_bytes = excluded.ingress_bytes,
    egress_bytes = excluded.egress_bytes,
    complete = excluded.complete
RETURNING id;

-- name: GetRouteUsageBucket :one
SELECT *
FROM route_usage_buckets
WHERE route_id = sqlc.arg(route_id)
    AND generation = sqlc.arg(generation)
    AND resolution = sqlc.arg(resolution)
    AND bucket_start_ns = sqlc.arg(bucket_start_ns);

-- name: ListIncompleteRouteUsageBuckets :many
SELECT *
FROM route_usage_buckets
WHERE complete = 0
ORDER BY bucket_start_ns, route_id, generation, resolution;

-- name: DeleteAcknowledgedRouteUsageBucket :execrows
DELETE FROM route_usage_buckets
WHERE id = sqlc.arg(id)
    AND complete = 1
    AND NOT EXISTS (
        SELECT 1
        FROM route_export_outbox
        WHERE source_kind = 'usage_snapshot'
            AND source_id = route_usage_buckets.id
    );

-- name: DeleteExpiredRouteLifecycleEvents :exec
DELETE FROM route_lifecycle_events
WHERE id IN (
    SELECT event.id
    FROM route_lifecycle_events AS event
    WHERE event.occurred_at_ns < sqlc.arg(cutoff_ns)
        AND NOT EXISTS (
            SELECT 1
            FROM route_export_outbox
            WHERE source_kind = 'lifecycle_event'
                AND source_id = event.id
        )
    ORDER BY event.occurred_at_ns, event.id
    LIMIT sqlc.arg(batch_size)
);
