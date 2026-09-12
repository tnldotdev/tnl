-- name: EnsureRouteUsageConfiguration :one
INSERT INTO control.route_usage_configuration (
    singleton,
    visitor_network_hash_master_key,
    created_at
) VALUES (
    true,
    sqlc.arg(visitor_network_hash_master_key),
    sqlc.arg(created_at)
)
ON CONFLICT (singleton) DO UPDATE SET singleton = EXCLUDED.singleton
RETURNING *;

-- name: EnsureIngressUsageRun :one
INSERT INTO control.ingress_usage_runs (
    ingress_id,
    ingress_run_id,
    ingress_lease_revision,
    started_at,
    lease_expires_at,
    observed_through
) VALUES (
    sqlc.arg(ingress_id),
    sqlc.arg(ingress_run_id),
    sqlc.arg(ingress_lease_revision),
    sqlc.arg(started_at),
    sqlc.arg(lease_expires_at),
    sqlc.arg(observed_through)
)
ON CONFLICT (ingress_id, ingress_run_id) DO UPDATE SET
    ingress_lease_revision = EXCLUDED.ingress_lease_revision,
    lease_expires_at = GREATEST(control.ingress_usage_runs.lease_expires_at, EXCLUDED.lease_expires_at)
WHERE control.ingress_usage_runs.ingress_lease_revision = EXCLUDED.ingress_lease_revision
RETURNING *;

-- name: ListLatestIngressUsageReports :many
-- The ingress/run guards serialize this source's append-only history. Fetch only
-- bounded metadata, not histogram blobs; exact replays still load their payload.
WITH requested AS (
    SELECT DISTINCT unnest(sqlc.arg(route_ids)::text[]) AS route_id,
                    unnest(sqlc.arg(route_versions)::bigint[]) AS route_version,
                    unnest(sqlc.arg(bucket_starts)::timestamptz[]) AS bucket_start
)
SELECT reports.route_id, reports.route_version, reports.bucket_start, reports.bucket_end,
       reports.observed_through, reports.report_revision, reports.connection_attempts,
       reports.policy_denials, reports.capacity_denials, reports.visitor_stream_open_failures,
       reports.successful_streams, reports.connection_nanoseconds, reports.ingress_bytes,
       reports.egress_bytes, reports.final
FROM requested
CROSS JOIN LATERAL (
    SELECT history.* FROM control.ingress_usage_reports AS history
    WHERE history.ingress_id = sqlc.arg(ingress_id)
      AND history.ingress_run_id = sqlc.arg(ingress_run_id)
      AND history.route_id = requested.route_id
      AND history.route_version = requested.route_version
      AND history.bucket_start = requested.bucket_start
    ORDER BY history.report_revision DESC
    LIMIT 1
) AS reports;

-- name: GetIngressUsageReport :one
SELECT *
FROM control.ingress_usage_reports
WHERE ingress_id = sqlc.arg(ingress_id)
  AND ingress_run_id = sqlc.arg(ingress_run_id)
  AND route_id = sqlc.arg(route_id)
  AND route_version = sqlc.arg(route_version)
  AND bucket_start = sqlc.arg(bucket_start)
  AND report_revision = sqlc.arg(report_revision);

-- name: LockRouteSessionForUsage :one
-- Acquire the immutable route reference before the session, in one round trip.
-- Read the bucket in a LATER statement: a competing ingress may create it while
-- this statement waits for the session lock, after this statement's snapshot.
WITH route_guard AS MATERIALIZED (
    SELECT routes.id FROM control.routes AS routes
    WHERE routes.id = sqlc.arg(route_id)
    FOR KEY SHARE
)
SELECT sessions.*
FROM control.route_sessions AS sessions
JOIN route_guard ON route_guard.id = sessions.route_id
WHERE sessions.route_version = sqlc.arg(route_version)
FOR UPDATE OF sessions;

-- name: LockRouteForUsage :one
SELECT id
FROM control.routes
WHERE id = sqlc.arg(route_id)
FOR KEY SHARE;

-- name: GetRouteUsageBucketForUpdate :one
SELECT *
FROM control.route_usage_buckets
WHERE route_id = sqlc.arg(route_id)
  AND route_version = sqlc.arg(route_version)
  AND bucket_start = sqlc.arg(bucket_start)
FOR UPDATE;

-- name: ApplyIngressUsageReport :one
-- The caller holds the ingress/run, route/session and existing bucket guards.
-- Dependencies make the immutable report, aggregate delta and denial update
-- one ordered write command. The caller checks insertion/aggregation and any
-- nonzero denial delta, rolling back all writes if a required step was rejected.
WITH report AS (
INSERT INTO control.ingress_usage_reports (
    ingress_id,
    ingress_run_id,
    route_id,
    route_version,
    bucket_start,
    bucket_end,
    observed_through,
    report_revision,
    connection_attempts,
    policy_denials,
    capacity_denials,
    visitor_stream_open_failures,
    successful_streams,
    connection_nanoseconds,
    ingress_bytes,
    egress_bytes,
    histogram_data,
    final,
    received_at
) VALUES (
    sqlc.arg(ingress_id),
    sqlc.arg(ingress_run_id),
    sqlc.arg(route_id),
    sqlc.arg(route_version),
    sqlc.arg(bucket_start),
    sqlc.arg(bucket_end),
    sqlc.arg(observed_through),
    sqlc.arg(report_revision),
    sqlc.arg(connection_attempts),
    sqlc.arg(policy_denials),
    sqlc.arg(capacity_denials),
    sqlc.arg(visitor_stream_open_failures),
    sqlc.arg(successful_streams),
    sqlc.arg(connection_nanoseconds),
    sqlc.arg(ingress_bytes),
    sqlc.arg(egress_bytes),
    sqlc.arg(histogram_data),
    sqlc.arg(final),
    sqlc.arg(received_at)
)
ON CONFLICT (ingress_id, ingress_run_id, route_id, route_version, bucket_start, report_revision)
DO NOTHING
RETURNING route_id, route_version
), bucket AS (
INSERT INTO control.route_usage_buckets (
    route_id,
    route_version,
    team_id,
    acting_identity_id,
    bucket_start,
    bucket_end,
    observed_through,
    connection_attempts,
    policy_denials,
    capacity_denials,
    visitor_stream_open_failures,
    successful_streams,
    connection_nanoseconds,
    ingress_bytes,
    egress_bytes,
    histogram_data,
    finalized,
    complete,
    finalized_at,
    updated_at
)
SELECT
    sessions.route_id,
    sessions.route_version,
    sessions.team_id,
    sessions.acting_identity_id,
    sqlc.arg(bucket_start),
    sqlc.arg(bucket_end),
    sqlc.arg(observed_through),
    sqlc.arg(delta_connection_attempts)::bigint,
    sqlc.arg(delta_policy_denials)::bigint,
    sqlc.arg(delta_capacity_denials)::bigint,
    sqlc.arg(delta_visitor_stream_open_failures)::bigint,
    sqlc.arg(delta_successful_streams)::bigint,
    sqlc.arg(delta_connection_nanoseconds)::bigint,
    sqlc.arg(delta_ingress_bytes)::bigint,
    sqlc.arg(delta_egress_bytes)::bigint,
    sqlc.arg(merged_histogram_data)::bytea,
    false,
    false,
    NULL,
    sqlc.arg(received_at)
FROM control.route_sessions AS sessions
JOIN report ON report.route_id = sessions.route_id AND report.route_version = sessions.route_version
ON CONFLICT (route_id, route_version, bucket_start) DO UPDATE SET
    bucket_end = GREATEST(control.route_usage_buckets.bucket_end, EXCLUDED.bucket_end),
    bucket_revision = control.route_usage_buckets.bucket_revision + 1,
    observed_through = GREATEST(control.route_usage_buckets.observed_through, EXCLUDED.observed_through),
    connection_attempts = control.route_usage_buckets.connection_attempts + EXCLUDED.connection_attempts,
    policy_denials = control.route_usage_buckets.policy_denials + EXCLUDED.policy_denials,
    capacity_denials = control.route_usage_buckets.capacity_denials + EXCLUDED.capacity_denials,
    visitor_stream_open_failures = control.route_usage_buckets.visitor_stream_open_failures + EXCLUDED.visitor_stream_open_failures,
    successful_streams = control.route_usage_buckets.successful_streams + EXCLUDED.successful_streams,
    connection_nanoseconds = control.route_usage_buckets.connection_nanoseconds + EXCLUDED.connection_nanoseconds,
    ingress_bytes = control.route_usage_buckets.ingress_bytes + EXCLUDED.ingress_bytes,
    egress_bytes = control.route_usage_buckets.egress_bytes + EXCLUDED.egress_bytes,
    histogram_data = EXCLUDED.histogram_data,
    updated_at = EXCLUDED.updated_at
WHERE NOT control.route_usage_buckets.finalized
RETURNING route_id, route_version
), denials AS (
UPDATE control.route_sessions AS sessions
SET policy_denials = sessions.policy_denials + sqlc.arg(delta_policy_denials)::bigint
FROM bucket
WHERE sessions.route_id = bucket.route_id
  AND sessions.route_version = bucket.route_version
  AND sqlc.arg(delta_policy_denials)::bigint > 0
  AND sessions.policy_denials <= 9223372036854775807 - sqlc.arg(delta_policy_denials)::bigint
RETURNING sessions.id
)
SELECT EXISTS (SELECT 1 FROM report) AS report_inserted,
       EXISTS (SELECT 1 FROM bucket) AS bucket_updated,
       EXISTS (SELECT 1 FROM denials) AS policy_denials_updated;

-- name: MarkIngressUsageRunReported :one
UPDATE control.ingress_usage_runs AS runs
SET last_reported_at = GREATEST(COALESCE(runs.last_reported_at, sqlc.arg(reported_at)), sqlc.arg(reported_at)),
    observed_through = GREATEST(runs.observed_through, COALESCE(sqlc.narg(observed_through)::timestamptz, runs.observed_through)),
    ended_at = CASE WHEN sqlc.arg(complete)::boolean THEN sqlc.narg(observed_through)::timestamptz ELSE runs.ended_at END,
    coverage_complete = runs.coverage_complete OR sqlc.arg(complete)::boolean
WHERE runs.ingress_id = sqlc.arg(ingress_id)
  AND runs.ingress_run_id = sqlc.arg(ingress_run_id)
  AND runs.ingress_lease_revision = sqlc.arg(ingress_lease_revision)
  AND (sqlc.narg(observed_through)::timestamptz IS NULL OR runs.observed_through <= sqlc.narg(observed_through)::timestamptz)
  AND (
      NOT runs.coverage_complete
      OR (
          sqlc.arg(complete)::boolean
          AND runs.observed_through = sqlc.narg(observed_through)::timestamptz
      )
  )
RETURNING *;

-- name: MarkExpiredIngressUsageRunIncomplete :exec
UPDATE control.ingress_usage_runs
SET ended_at = COALESCE(ended_at, sqlc.arg(ended_at)),
    incomplete_from = observed_through,
    incomplete_until = sqlc.arg(ended_at)
WHERE ingress_id = sqlc.arg(ingress_id)
  AND ingress_run_id = sqlc.arg(ingress_run_id)
  AND ended_at IS NULL;

-- name: MarkExpiredIngressUsageRunsIncomplete :many
UPDATE control.ingress_usage_runs
SET ended_at = lease_expires_at,
    incomplete_from = observed_through,
    incomplete_until = lease_expires_at
WHERE ended_at IS NULL
  AND lease_expires_at <= sqlc.arg(now)
RETURNING *;

-- name: FinalizeRouteUsageBuckets :many
WITH finalizable AS (
    SELECT
        buckets.bucket_id,
        NOT EXISTS (
            SELECT 1
            FROM control.ingress_usage_runs AS incomplete
            WHERE incomplete.incomplete_from < buckets.bucket_end
              AND incomplete.incomplete_until > buckets.bucket_start
        ) AS complete
    FROM control.route_usage_buckets AS buckets
    WHERE NOT buckets.finalized
      AND buckets.bucket_end <= sqlc.arg(through)
      AND NOT EXISTS (
          SELECT 1
          FROM control.ingress_usage_runs AS runs
          WHERE runs.ended_at IS NULL
            AND runs.started_at < buckets.bucket_end
            AND runs.observed_through < buckets.bucket_end
      )
    FOR UPDATE OF buckets
)
UPDATE control.route_usage_buckets AS buckets
SET finalized = true,
    complete = finalizable.complete,
    observed_through = CASE
        WHEN finalizable.complete THEN buckets.bucket_end
        ELSE buckets.observed_through
    END,
    finalized_at = sqlc.arg(finalized_at),
    updated_at = sqlc.arg(finalized_at)
FROM finalizable
WHERE buckets.bucket_id = finalizable.bucket_id
RETURNING buckets.*;

-- name: InsertRouteUsageDelivery :one
INSERT INTO control.route_usage_deliveries (
    bucket_id,
    source_revision,
    delivery_key,
    state,
    available_at,
    created_at
) VALUES (
    sqlc.arg(bucket_id),
    sqlc.arg(source_revision),
    sqlc.arg(delivery_key),
    'pending',
    sqlc.arg(available_at),
    sqlc.arg(created_at)
)
ON CONFLICT (bucket_id, source_revision) DO UPDATE SET
    delivery_key = control.route_usage_deliveries.delivery_key
RETURNING *;

-- name: ClaimRouteUsageDeliveries :many
WITH candidates AS (
    SELECT delivery_id
    FROM control.route_usage_deliveries
    WHERE (
        state IN ('pending', 'failed')
        AND available_at <= sqlc.arg(claimed_at)
    ) OR (
        state = 'delivering'
        AND work_expires_at <= sqlc.arg(claimed_at)
    )
    ORDER BY available_at, delivery_id
    LIMIT sqlc.arg(batch_size)
    FOR UPDATE SKIP LOCKED
)
UPDATE control.route_usage_deliveries AS deliveries
SET state = 'delivering',
    work_owner = sqlc.arg(work_owner),
    work_epoch = deliveries.work_epoch + 1,
    work_expires_at = sqlc.arg(work_expires_at),
    attempts = deliveries.attempts + 1,
    last_attempted_at = sqlc.arg(claimed_at),
    last_error = NULL
FROM candidates
WHERE deliveries.delivery_id = candidates.delivery_id
RETURNING deliveries.*;

-- name: GetRouteUsageBucketByID :one
SELECT *
FROM control.route_usage_buckets
WHERE bucket_id = sqlc.arg(bucket_id)
  AND finalized;

-- name: CompleteRouteUsageDelivery :one
UPDATE control.route_usage_deliveries
SET state = 'delivered',
    work_owner = NULL,
    work_expires_at = NULL,
    delivered_at = sqlc.arg(completed_at),
    last_error = NULL
WHERE delivery_id = sqlc.arg(delivery_id)
  AND state = 'delivering'
  AND work_owner = sqlc.arg(work_owner)
  AND work_epoch = sqlc.arg(work_epoch)
  AND work_expires_at > sqlc.arg(completed_at)
RETURNING *;

-- name: RetryRouteUsageDelivery :one
UPDATE control.route_usage_deliveries
SET state = 'failed',
    work_owner = NULL,
    work_expires_at = NULL,
    available_at = sqlc.arg(available_at),
    last_error = sqlc.arg(last_error)
WHERE delivery_id = sqlc.arg(delivery_id)
  AND state = 'delivering'
  AND work_owner = sqlc.arg(work_owner)
  AND work_epoch = sqlc.arg(work_epoch)
  AND work_expires_at > sqlc.arg(completed_at)
RETURNING *;
