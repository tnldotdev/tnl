-- Find an old committed PREFIX, not the largest old timestamp. Request-start
-- timestamps can be out of revision order; preserve every still-recent event.
-- This scan happens before acquiring the publication clock.
-- name: SelectIngressRoutingRetentionFloor :one
SELECT GREATEST(clock.retained_after_revision, LEAST(clock.current_revision,
    COALESCE((SELECT min(events.routing_table_revision) - 1
              FROM control.ingress_routing_table_events AS events
              WHERE events.created_at >= sqlc.arg(cutoff)
                AND events.routing_table_revision > clock.retained_after_revision), clock.current_revision)))::bigint AS revision
FROM control.ingress_routing_table_clock AS clock
WHERE clock.singleton = true;

-- Commit this short clock update BEFORE pruning in a different transaction.
-- A crash in between retains excess data, never an advertised but missing suffix.
-- name: AdvanceIngressRoutingRetentionFloor :one
UPDATE control.ingress_routing_table_clock
SET retained_after_revision = GREATEST(retained_after_revision, sqlc.arg(revision)::bigint)
WHERE singleton = true AND current_revision >= sqlc.arg(revision)::bigint
RETURNING retained_after_revision;

-- Cleanup-only coordination; no public URL, reservation, service, lease, or clock locks.
-- name: TryLockIngressRoutingHistoryCleanup :one
SELECT pg_try_advisory_xact_lock(hashtextextended('tnl:routing-history-cleanup', 0));

-- Bound candidates visited as well as rows deleted. Advance past anchors even
-- when no row can be removed. Keep the newest hostname/category projection
-- (including tombstones/expired entries) AND each publish run number's latest revision.
-- All checks use this statement's snapshot. Concurrent publications can only
-- make an old anchor redundant; they cannot make a superseded event current.
-- name: PruneIngressRoutingHistoryBatch :one
WITH candidates AS MATERIALIZED (
    SELECT events.routing_table_revision, events.canonical_hostname,
           events.event_kind, events.public_url_id, events.publish_run_number
    FROM control.ingress_routing_table_events AS events
    WHERE events.routing_table_revision > sqlc.arg(after_revision)::bigint
      AND events.routing_table_revision <= (
          SELECT retained_after_revision FROM control.ingress_routing_table_clock WHERE singleton = true
      )
    ORDER BY events.routing_table_revision
    LIMIT 1000
), deleted AS (
    DELETE FROM control.ingress_routing_table_events AS events
    USING candidates
    WHERE events.routing_table_revision = candidates.routing_table_revision
      AND EXISTS (
          SELECT 1 FROM control.ingress_routing_table_events AS newer
          WHERE newer.canonical_hostname = candidates.canonical_hostname
            AND (newer.event_kind IN ('public_url_upsert', 'public_url_tombstone')) =
                (candidates.event_kind IN ('public_url_upsert', 'public_url_tombstone'))
            AND newer.routing_table_revision > candidates.routing_table_revision
      )
      AND EXISTS (
          SELECT 1 FROM control.ingress_routing_table_events AS newer
          WHERE newer.public_url_id = candidates.public_url_id
            AND newer.publish_run_number = candidates.publish_run_number
            AND newer.routing_table_revision > candidates.routing_table_revision
      )
    RETURNING events.routing_table_revision
)
SELECT COALESCE(max(candidates.routing_table_revision), sqlc.arg(after_revision)::bigint)::bigint AS next_revision,
       count(*)::bigint AS scanned,
       (SELECT count(*) FROM deleted)::bigint AS deleted
FROM candidates;
