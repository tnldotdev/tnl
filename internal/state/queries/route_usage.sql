-- name: AdvanceRouteLifecycleSequence :one
UPDATE routes
SET lifecycle_sequence = lifecycle_sequence + 1
WHERE id = sqlc.arg(route_id)
RETURNING lifecycle_sequence;

-- name: CountRouteLifecycleTransition :one
SELECT COUNT(*)
FROM route_lifecycle_events
WHERE route_id = sqlc.arg(route_id)
    AND version = sqlc.arg(version)
    AND transition = sqlc.arg(transition);

-- name: InsertRouteLifecycleEvent :one
INSERT INTO route_lifecycle_events (
    event_id,
    route_id,
    version,
    sequence,
    occurred_at,
    transition
) VALUES (
    sqlc.arg(event_id),
    sqlc.arg(route_id),
    sqlc.arg(version),
    sqlc.arg(sequence),
    sqlc.arg(occurred_at),
    sqlc.arg(transition)
)
RETURNING id;

-- name: UpsertRouteUsageOutbox :exec
INSERT INTO route_usage_outbox_items (
    source_kind,
    source_id,
    source_revision,
    enqueued_at
) VALUES (
    sqlc.arg(source_kind),
    sqlc.arg(source_id),
    sqlc.arg(source_revision),
    sqlc.arg(enqueued_at)
)
ON CONFLICT (source_kind, source_id) DO UPDATE SET
    source_revision = excluded.source_revision,
    enqueued_at = excluded.enqueued_at
WHERE excluded.source_revision > route_usage_outbox_items.source_revision;

-- name: GetNextLifecycleReport :one
SELECT
    sqlc.embed(route_lifecycle_events),
    route_usage_outbox_items.source_revision,
    route_usage_outbox_items.enqueued_at
FROM route_usage_outbox_items
JOIN route_lifecycle_events ON route_lifecycle_events.id = route_usage_outbox_items.source_id
WHERE route_usage_outbox_items.source_kind = 'lifecycle_event'
ORDER BY route_usage_outbox_items.enqueued_at, route_usage_outbox_items.source_id
LIMIT 1;

-- name: GetNextUsageReport :one
SELECT
    sqlc.embed(route_usage_snapshots),
    route_usage_outbox_items.source_revision,
    route_usage_outbox_items.enqueued_at
FROM route_usage_outbox_items
JOIN route_usage_snapshots ON route_usage_snapshots.id = route_usage_outbox_items.source_id
WHERE route_usage_outbox_items.source_kind = 'usage_snapshot'
ORDER BY route_usage_outbox_items.enqueued_at, route_usage_outbox_items.source_id
LIMIT 1;

-- name: DeleteRouteUsageOutboxRevision :execrows
DELETE FROM route_usage_outbox_items
WHERE source_kind = sqlc.arg(source_kind)
    AND source_id = sqlc.arg(source_id)
    AND source_revision = sqlc.arg(source_revision);

-- name: CountRouteUsageOutboxByKind :one
SELECT COUNT(*)
FROM route_usage_outbox_items
WHERE source_kind = sqlc.arg(source_kind);

-- name: GetOldestRouteUsageOutboxTime :one
SELECT enqueued_at
FROM route_usage_outbox_items
ORDER BY enqueued_at
LIMIT 1;

-- name: UpsertRouteUsageSnapshot :one
INSERT INTO route_usage_snapshots (
    route_id,
    version,
    resolution,
    bucket_start,
    revision,
    observed_through,
    connections_opened,
    connection_nanoseconds,
    ingress_bytes,
    egress_bytes,
    complete
) VALUES (
    sqlc.arg(route_id),
    sqlc.arg(version),
    sqlc.arg(resolution),
    sqlc.arg(bucket_start),
    sqlc.arg(revision),
    sqlc.arg(observed_through),
    sqlc.arg(connections_opened),
    sqlc.arg(connection_nanoseconds),
    sqlc.arg(ingress_bytes),
    sqlc.arg(egress_bytes),
    sqlc.arg(complete)
)
ON CONFLICT (route_id, version, resolution, bucket_start) DO UPDATE SET
    revision = excluded.revision,
    observed_through = excluded.observed_through,
    connections_opened = excluded.connections_opened,
    connection_nanoseconds = excluded.connection_nanoseconds,
    ingress_bytes = excluded.ingress_bytes,
    egress_bytes = excluded.egress_bytes,
    complete = excluded.complete
RETURNING id;

-- name: GetRouteUsageSnapshot :one
SELECT *
FROM route_usage_snapshots
WHERE route_id = sqlc.arg(route_id)
    AND version = sqlc.arg(version)
    AND resolution = sqlc.arg(resolution)
    AND bucket_start = sqlc.arg(bucket_start);

-- name: ListIncompleteRouteUsageSnapshots :many
SELECT *
FROM route_usage_snapshots
WHERE complete = 0
ORDER BY bucket_start, route_id, version, resolution;

-- name: DeleteAcknowledgedRouteUsageSnapshot :execrows
DELETE FROM route_usage_snapshots
WHERE id = sqlc.arg(id)
    AND complete = 1
    AND NOT EXISTS (
        SELECT 1
        FROM route_usage_outbox_items
        WHERE source_kind = 'usage_snapshot'
            AND source_id = route_usage_snapshots.id
    );

-- name: DeleteExpiredRouteLifecycleEvents :exec
DELETE FROM route_lifecycle_events
WHERE id IN (
    SELECT event.id
    FROM route_lifecycle_events AS event
    WHERE event.occurred_at < sqlc.arg(cutoff)
        AND NOT EXISTS (
            SELECT 1
            FROM route_usage_outbox_items
            WHERE source_kind = 'lifecycle_event'
                AND source_id = event.id
        )
    ORDER BY event.occurred_at, event.id
    LIMIT sqlc.arg(batch_size)
);
