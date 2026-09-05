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

-- name: GetLatestIngressUsageReport :one
SELECT *
FROM control.ingress_usage_reports
WHERE ingress_id = sqlc.arg(ingress_id)
  AND ingress_run_id = sqlc.arg(ingress_run_id)
  AND route_id = sqlc.arg(route_id)
  AND route_version = sqlc.arg(route_version)
  AND bucket_start = sqlc.arg(bucket_start)
ORDER BY report_revision DESC
LIMIT 1
FOR UPDATE;

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
SELECT *
FROM control.route_sessions
WHERE route_id = sqlc.arg(route_id)
  AND route_version = sqlc.arg(route_version)
FOR UPDATE;

-- name: GetRouteUsageBucketForUpdate :one
SELECT *
FROM control.route_usage_buckets
WHERE route_id = sqlc.arg(route_id)
  AND route_version = sqlc.arg(route_version)
  AND bucket_start = sqlc.arg(bucket_start)
FOR UPDATE;

-- name: InsertIngressUsageReport :one
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
    publisher_open_failures,
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
    sqlc.arg(publisher_open_failures),
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
RETURNING *;

-- name: ApplyIngressUsageDelta :one
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
    publisher_open_failures,
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
    sqlc.arg(connection_attempts),
    sqlc.arg(policy_denials),
    sqlc.arg(capacity_denials),
    sqlc.arg(publisher_open_failures),
    sqlc.arg(successful_streams),
    sqlc.arg(connection_nanoseconds),
    sqlc.arg(ingress_bytes),
    sqlc.arg(egress_bytes),
    sqlc.arg(histogram_data),
    false,
    false,
    NULL,
    sqlc.arg(updated_at)
FROM control.route_sessions AS sessions
WHERE sessions.route_id = sqlc.arg(route_id)
  AND sessions.route_version = sqlc.arg(route_version)
ON CONFLICT (route_id, route_version, bucket_start) DO UPDATE SET
    bucket_end = GREATEST(control.route_usage_buckets.bucket_end, EXCLUDED.bucket_end),
    bucket_revision = control.route_usage_buckets.bucket_revision + 1,
    observed_through = GREATEST(control.route_usage_buckets.observed_through, EXCLUDED.observed_through),
    connection_attempts = control.route_usage_buckets.connection_attempts + EXCLUDED.connection_attempts,
    policy_denials = control.route_usage_buckets.policy_denials + EXCLUDED.policy_denials,
    capacity_denials = control.route_usage_buckets.capacity_denials + EXCLUDED.capacity_denials,
    publisher_open_failures = control.route_usage_buckets.publisher_open_failures + EXCLUDED.publisher_open_failures,
    successful_streams = control.route_usage_buckets.successful_streams + EXCLUDED.successful_streams,
    connection_nanoseconds = control.route_usage_buckets.connection_nanoseconds + EXCLUDED.connection_nanoseconds,
    ingress_bytes = control.route_usage_buckets.ingress_bytes + EXCLUDED.ingress_bytes,
    egress_bytes = control.route_usage_buckets.egress_bytes + EXCLUDED.egress_bytes,
    histogram_data = EXCLUDED.histogram_data,
    updated_at = EXCLUDED.updated_at
WHERE NOT control.route_usage_buckets.finalized
RETURNING *;

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
UPDATE control.route_usage_buckets
SET finalized = true,
    complete = NOT EXISTS (
        SELECT 1
        FROM control.ingress_usage_runs AS incomplete
        WHERE incomplete.incomplete_from < control.route_usage_buckets.bucket_end
          AND incomplete.incomplete_until > control.route_usage_buckets.bucket_start
    ),
    finalized_at = sqlc.arg(finalized_at),
    updated_at = sqlc.arg(finalized_at)
WHERE NOT finalized
  AND bucket_end <= sqlc.arg(through)
  AND NOT EXISTS (
      SELECT 1
      FROM control.ingress_usage_runs AS runs
      WHERE runs.ended_at IS NULL
        AND runs.started_at < control.route_usage_buckets.bucket_end
        AND runs.observed_through < control.route_usage_buckets.bucket_end
  )
RETURNING *;

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
