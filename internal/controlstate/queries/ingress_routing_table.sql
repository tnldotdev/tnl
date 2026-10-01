-- name: ReadIngressRoutingTableClock :one
SELECT *
FROM control.ingress_routing_table_clock
WHERE id = 1;

-- name: LockIngressRoutingTableClock :one
SELECT current_revision
FROM control.ingress_routing_table_clock
WHERE id = 1
FOR UPDATE;

-- name: ListIngressRoutingTableSnapshot :many
-- select the latest revision for each entry before filtering kind or expiry;
-- filtering first could revive a superseded public URL or challenge.
WITH latest AS (
    SELECT max(history.id) AS routing_table_revision
    FROM control.ingress_routing_table_events AS history
    WHERE history.id <= sqlc.arg(through_revision)
    GROUP BY history.canonical_hostname,
        CASE WHEN history.event_kind IN ('public_url_upsert', 'public_url_tombstone') THEN 'public_url' ELSE 'challenge' END
)
SELECT events.*
FROM latest
JOIN control.ingress_routing_table_events AS events ON events.id = latest.routing_table_revision
WHERE events.event_kind IN ('public_url_upsert', 'challenge_upsert')
  AND events.public_url_expires_at > sqlc.arg(now)
ORDER BY events.canonical_hostname;

-- name: ListIngressRoutingTableEvents :many
SELECT *
FROM control.ingress_routing_table_events
WHERE id > sqlc.arg(after_revision)
  AND id <= sqlc.arg(through_revision)
ORDER BY id
LIMIT sqlc.arg(page_limit);

-- name: LatestIngressRoutingEntryRevision :one
SELECT COALESCE((
    SELECT entry_revision
    FROM control.ingress_routing_table_events
    WHERE public_url_id = sqlc.arg(public_url_id)
      AND publish_run_number = sqlc.arg(publish_run_number)
    ORDER BY id DESC
    LIMIT 1
), 0)::bigint;

-- name: InsertIngressRoutingTableEvent :one
INSERT INTO control.ingress_routing_table_events (
    event_kind,
    public_url_id,
    publish_run_number,
    canonical_hostname,
    entry_revision,
    projection,
    public_url_expires_at,
    created_at
) VALUES (
    sqlc.arg(event_kind),
    sqlc.arg(public_url_id),
    sqlc.arg(publish_run_number),
    sqlc.arg(canonical_hostname),
    sqlc.arg(entry_revision),
    sqlc.arg(projection),
    sqlc.narg(public_url_expires_at),
    sqlc.arg(created_at)
)
RETURNING id;

-- name: InsertFinalIngressRoutingTableEvent :one
-- take the routing clock before allocating the revision in this command.
-- single-event publishers avoid an extra round trip; multi-event publishers
-- already hold the clock. keep it through commit to preserve revision order.
WITH clock_guard AS MATERIALIZED (
    SELECT current_revision
    FROM control.ingress_routing_table_clock
    WHERE id = 1
    FOR UPDATE
), inserted AS (
    INSERT INTO control.ingress_routing_table_events (
        event_kind,
        public_url_id,
        publish_run_number,
        canonical_hostname,
        entry_revision,
        projection,
        public_url_expires_at,
        created_at
    ) SELECT
        sqlc.arg(event_kind),
        sqlc.arg(public_url_id),
        sqlc.arg(publish_run_number),
        sqlc.arg(canonical_hostname),
        sqlc.arg(entry_revision),
        sqlc.arg(projection),
        sqlc.narg(public_url_expires_at),
        sqlc.arg(created_at)
    FROM clock_guard
    RETURNING id AS routing_table_revision
), advanced AS (
    UPDATE control.ingress_routing_table_clock
    SET current_revision = inserted.routing_table_revision,
        updated_at = sqlc.arg(updated_at)
    FROM inserted
    WHERE id = 1
      AND current_revision < inserted.routing_table_revision
    RETURNING control.ingress_routing_table_clock.current_revision
)
SELECT current_revision AS routing_table_revision
FROM advanced;
