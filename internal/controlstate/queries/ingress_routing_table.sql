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
-- Group only entry keys and revisions across history, then fetch the selected
-- payloads. Filter after selection so tombstones/expiry cannot revive old rows.
WITH latest AS (
    SELECT max(history.routing_table_revision) AS routing_table_revision
    FROM control.ingress_routing_table_events AS history
    WHERE history.routing_table_revision <= sqlc.arg(through_revision)
    GROUP BY history.canonical_hostname,
        CASE WHEN history.event_kind IN ('public_url_upsert', 'public_url_tombstone') THEN 'route' ELSE 'challenge' END
)
SELECT events.*
FROM latest
JOIN control.ingress_routing_table_events AS events ON events.routing_table_revision = latest.routing_table_revision
WHERE events.event_kind IN ('public_url_upsert', 'challenge_upsert')
  AND events.public_url_expires_at > sqlc.arg(now)
ORDER BY events.canonical_hostname;

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
    WHERE public_url_id = sqlc.arg(public_url_id)
      AND publish_run_number = sqlc.arg(publish_run_number)
    ORDER BY routing_table_revision DESC
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
RETURNING routing_table_revision;

-- name: InsertFinalIngressRoutingTableEvent :one
-- Acquire the clock before identity allocation in this same command. Single-event
-- publishers avoid a separate round trip while holding the global clock; callers
-- with earlier events already hold it. Keep the lock through transaction commit.
WITH clock_guard AS MATERIALIZED (
    SELECT current_revision
    FROM control.ingress_routing_table_clock
    WHERE singleton = true
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
    RETURNING routing_table_revision
), advanced AS (
    UPDATE control.ingress_routing_table_clock
    SET current_revision = inserted.routing_table_revision,
        updated_at = sqlc.arg(updated_at)
    FROM inserted
    WHERE singleton = true
      AND current_revision < inserted.routing_table_revision
    RETURNING control.ingress_routing_table_clock.current_revision
)
SELECT current_revision AS routing_table_revision
FROM advanced;
