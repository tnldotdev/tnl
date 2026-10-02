-- find a committed prefix, not the largest old timestamp: request-start times
-- can be out of revision order. keep every recent event without taking the
-- publication clock during this scan.
-- name: SelectIngressRoutingRetentionFloor :one
SELECT GREATEST(clock.retained_after_revision, LEAST(clock.current_revision,
    COALESCE((SELECT min(events.id) - 1
              FROM control.ingress_routing_table_events AS events
              WHERE events.created_at >= sqlc.arg(cutoff)
                AND events.id > clock.retained_after_revision), clock.current_revision)))::bigint AS revision
FROM control.ingress_routing_table_clock AS clock
WHERE clock.id = 1;

-- commit the retention floor before pruning in another transaction. a crash
-- between them retains extra rows, never a missing advertised suffix.
-- name: AdvanceIngressRoutingRetentionFloor :one
UPDATE control.ingress_routing_table_clock
SET retained_after_revision = GREATEST(retained_after_revision, sqlc.arg(revision)::bigint)
WHERE id = 1 AND current_revision >= sqlc.arg(revision)::bigint
RETURNING retained_after_revision;

-- cleanup-only coordination; do not take public URL, placement, lease, or routing clock locks.
-- name: TryLockIngressRoutingHistoryCleanup :one
SELECT pg_try_advisory_xact_lock(hashtextextended('tnl:routing-history-cleanup', 0));

-- bound candidates scanned, even when an anchor cannot be removed. retain the
-- latest hostname/category projection, including tombstones and expired rows,
-- and each publish run number's latest revision. concurrent publication can
-- make an anchor redundant but cannot restore a superseded event.
-- name: PruneIngressRoutingHistoryBatch :one
WITH candidates AS MATERIALIZED (
    SELECT events.id, events.canonical_hostname,
           events.event_kind, events.public_url_id, events.publish_run_number
    FROM control.ingress_routing_table_events AS events
    WHERE events.id > sqlc.arg(after_revision)::bigint
      AND events.id <= (
          SELECT retained_after_revision FROM control.ingress_routing_table_clock WHERE id = 1
      )
    ORDER BY events.id
    LIMIT 1000
), deleted AS (
    DELETE FROM control.ingress_routing_table_events AS events
    USING candidates
    WHERE events.id = candidates.id
      AND EXISTS (
          SELECT 1 FROM control.ingress_routing_table_events AS newer
          WHERE newer.canonical_hostname = candidates.canonical_hostname
            AND (newer.event_kind IN ('public_url_upsert', 'public_url_tombstone')) =
                (candidates.event_kind IN ('public_url_upsert', 'public_url_tombstone'))
            AND newer.id > candidates.id
      )
      AND EXISTS (
          SELECT 1 FROM control.ingress_routing_table_events AS newer
          WHERE newer.public_url_id = candidates.public_url_id
            AND newer.publish_run_number = candidates.publish_run_number
            AND newer.id > candidates.id
      )
    RETURNING events.id
)
SELECT COALESCE(max(candidates.id), sqlc.arg(after_revision)::bigint)::bigint AS next_revision,
       count(*)::bigint AS scanned,
       (SELECT count(*) FROM deleted)::bigint AS deleted
FROM candidates;
