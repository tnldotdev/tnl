-- name: ReadIngressRoutingTableClock :one
SELECT *
FROM control.ingress_routing_table_clock
WHERE singleton = true;

-- name: LockIngressRoutingTableClock :one
SELECT current_revision
FROM control.ingress_routing_table_clock
WHERE singleton = true
FOR UPDATE;

-- name: ListIngressRoutingTableSnapshot :many
WITH latest AS (
    SELECT DISTINCT ON (
        canonical_hostname,
        CASE WHEN event_kind IN ('route_upsert', 'route_tombstone') THEN 'route' ELSE 'challenge' END
    )
        routing_table_revision,
        event_kind,
        route_id,
        route_version,
        canonical_hostname,
        entry_revision,
        projection,
        route_expires_at,
        created_at
    FROM control.ingress_routing_table_events
    WHERE routing_table_revision <= sqlc.arg(through_revision)
    ORDER BY canonical_hostname,
        CASE WHEN event_kind IN ('route_upsert', 'route_tombstone') THEN 'route' ELSE 'challenge' END,
        routing_table_revision DESC
)
SELECT *
FROM latest
WHERE event_kind IN ('route_upsert', 'challenge_upsert')
  AND route_expires_at > sqlc.arg(now)
ORDER BY canonical_hostname;

-- name: ListIngressRoutingTableEvents :many
SELECT *
FROM control.ingress_routing_table_events
WHERE routing_table_revision > sqlc.arg(after_revision)
  AND routing_table_revision <= sqlc.arg(through_revision)
ORDER BY routing_table_revision
LIMIT sqlc.arg(page_limit);

-- name: LatestIngressRoutingEntryRevision :one
SELECT COALESCE((
    SELECT entry_revision
    FROM control.ingress_routing_table_events
    WHERE route_id = sqlc.arg(route_id)
      AND route_version = sqlc.arg(route_version)
    ORDER BY routing_table_revision DESC
    LIMIT 1
), 0)::bigint;

-- name: InsertIngressRoutingTableEvent :one
INSERT INTO control.ingress_routing_table_events (
    event_kind,
    route_id,
    route_version,
    canonical_hostname,
    entry_revision,
    projection,
    route_expires_at,
    created_at
) VALUES (
    sqlc.arg(event_kind),
    sqlc.arg(route_id),
    sqlc.arg(route_version),
    sqlc.arg(canonical_hostname),
    sqlc.arg(entry_revision),
    sqlc.arg(projection),
    sqlc.narg(route_expires_at),
    sqlc.arg(created_at)
)
RETURNING routing_table_revision;

-- name: AdvanceIngressRoutingTableClock :exec
UPDATE control.ingress_routing_table_clock
SET current_revision = sqlc.arg(routing_table_revision),
    updated_at = sqlc.arg(updated_at)
WHERE singleton = true
  AND current_revision < sqlc.arg(routing_table_revision);
