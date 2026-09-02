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

-- name: InsertRouteRegistration :one
INSERT INTO route_registrations (
    registration_id,
    route_id,
    hostname,
    signing_key_id,
    authorization_id,
    created_at,
    retry_id
) VALUES (
    sqlc.arg(registration_id),
    sqlc.arg(route_id),
    sqlc.arg(hostname),
    sqlc.arg(signing_key_id),
    sqlc.arg(authorization_id),
    sqlc.arg(created_at),
    sqlc.arg(retry_id)
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
    enqueued_at = excluded.enqueued_at,
    last_attempted_at = NULL
WHERE excluded.source_revision > route_usage_outbox_items.source_revision;

-- name: GetNextRouteUsageOutboxItem :one
SELECT outbox.*
FROM route_usage_outbox_items AS outbox
WHERE
    (outbox.source_kind = 'registration' AND EXISTS (
        SELECT 1 FROM route_registrations AS registration
        WHERE registration.id = outbox.source_id
    ))
    OR (outbox.source_kind = 'lifecycle_event' AND EXISTS (
        SELECT 1
        FROM route_lifecycle_events AS event
        JOIN routes AS route ON route.id = event.route_id
        WHERE event.id = outbox.source_id
            AND (
                route.authorization_id IS NULL OR EXISTS (
                    SELECT 1
                    FROM route_registrations AS registration
                    WHERE registration.route_id = event.route_id
                        AND registration.acknowledged_revision IS NOT NULL
                )
            )
            AND NOT EXISTS (
                SELECT 1
                FROM route_usage_outbox_items AS earlier_outbox
                JOIN route_lifecycle_events AS earlier_event
                    ON earlier_event.id = earlier_outbox.source_id
                WHERE earlier_outbox.source_kind = 'lifecycle_event'
                    AND earlier_event.route_id = event.route_id
                    AND earlier_event.sequence < event.sequence
            )
    ))
    OR (outbox.source_kind = 'usage_snapshot' AND EXISTS (
        SELECT 1
        FROM route_usage_snapshots AS snapshot
        JOIN route_usage_reports AS report ON report.snapshot_id = snapshot.id
        JOIN routes AS route ON route.id = snapshot.route_id
        WHERE snapshot.id = outbox.source_id
            AND report.revision = outbox.source_revision
            AND (
                route.authorization_id IS NULL OR EXISTS (
                    SELECT 1
                    FROM route_registrations AS registration
                    WHERE registration.route_id = snapshot.route_id
                        AND registration.acknowledged_revision IS NOT NULL
                )
            )
            AND EXISTS (
                SELECT 1
                FROM route_lifecycle_events AS started
                WHERE started.route_id = snapshot.route_id
                    AND started.version = snapshot.version
                    AND started.transition = 'version_started'
                    AND NOT EXISTS (
                        SELECT 1
                        FROM route_usage_outbox_items AS started_outbox
                        WHERE started_outbox.source_kind = 'lifecycle_event'
                            AND started_outbox.source_id = started.id
                    )
            )
    ))
ORDER BY
    coalesce(outbox.last_attempted_at, outbox.enqueued_at),
    CASE outbox.source_kind
        WHEN 'registration' THEN 0
        WHEN 'lifecycle_event' THEN 1
        ELSE 2
    END,
    outbox.source_id
LIMIT 1;

-- name: ListRouteLifecycleOutboxBatch :many
SELECT
    outbox.source_kind,
    outbox.source_id,
    outbox.source_revision,
    outbox.enqueued_at,
    outbox.last_attempted_at,
    event.event_id,
    event.route_id,
    event.version,
    event.sequence,
    event.occurred_at,
    event.transition
FROM route_usage_outbox_items AS outbox
JOIN route_lifecycle_events AS event ON event.id = outbox.source_id
JOIN routes AS route ON route.id = event.route_id
WHERE outbox.source_kind = 'lifecycle_event'
    AND (
        route.authorization_id IS NULL OR EXISTS (
            SELECT 1
            FROM route_registrations AS registration
            WHERE registration.route_id = event.route_id
                AND registration.acknowledged_revision IS NOT NULL
        )
    )
    AND NOT EXISTS (
        SELECT 1
        FROM route_usage_outbox_items AS earlier_outbox
        JOIN route_lifecycle_events AS earlier_event ON earlier_event.id = earlier_outbox.source_id
        WHERE earlier_outbox.source_kind = 'lifecycle_event'
            AND earlier_event.route_id = event.route_id
            AND earlier_event.sequence < event.sequence
    )
ORDER BY coalesce(outbox.last_attempted_at, outbox.enqueued_at), outbox.source_id
LIMIT sqlc.arg(batch_size);

-- name: ListRouteUsageOutboxBatch :many
SELECT
    outbox.source_kind,
    outbox.source_id,
    outbox.source_revision,
    outbox.enqueued_at,
    outbox.last_attempted_at,
    snapshot.route_id,
    snapshot.version,
    snapshot.resolution,
    snapshot.bucket_start,
    report.report_id,
    report.revision,
    report.observed_through,
    report.connection_attempts,
    report.policy_denials,
    report.capacity_denials,
    report.publisher_open_failures,
    report.successful_streams,
    report.connection_nanoseconds,
    report.ingress_bytes,
    report.egress_bytes,
    report.publisher_open_latency,
    report.time_to_first_publisher_byte,
    report.successful_connection_duration,
    report.visitor_network_hll,
    report.visitor_network_estimate,
    report.complete,
    snapshot.finalized
FROM route_usage_outbox_items AS outbox
JOIN route_usage_snapshots AS snapshot ON snapshot.id = outbox.source_id
JOIN route_usage_reports AS report
    ON report.snapshot_id = snapshot.id AND report.revision = outbox.source_revision
JOIN routes AS route ON route.id = snapshot.route_id
WHERE outbox.source_kind = 'usage_snapshot'
    AND (
        route.authorization_id IS NULL OR EXISTS (
            SELECT 1
            FROM route_registrations AS registration
            WHERE registration.route_id = snapshot.route_id
                AND registration.acknowledged_revision IS NOT NULL
        )
    )
    AND EXISTS (
        SELECT 1
        FROM route_lifecycle_events AS started
        WHERE started.route_id = snapshot.route_id
            AND started.version = snapshot.version
            AND started.transition = 'version_started'
            AND NOT EXISTS (
                SELECT 1
                FROM route_usage_outbox_items AS started_outbox
                WHERE started_outbox.source_kind = 'lifecycle_event'
                    AND started_outbox.source_id = started.id
            )
    )
ORDER BY coalesce(outbox.last_attempted_at, outbox.enqueued_at), outbox.source_id
LIMIT sqlc.arg(batch_size);

-- name: MarkRouteUsageOutboxAttempt :execrows
UPDATE route_usage_outbox_items
SET last_attempted_at = CAST(sqlc.arg(attempted_at) AS INTEGER)
WHERE source_kind = sqlc.arg(source_kind)
    AND source_id = sqlc.arg(source_id)
    AND source_revision = sqlc.arg(source_revision);

-- name: GetRouteRegistrationReport :one
SELECT *
FROM route_registrations
WHERE id = sqlc.arg(id);

-- name: AcknowledgeRouteRegistrationRevision :execrows
UPDATE route_registrations
SET
    acknowledged_revision = CAST(sqlc.arg(source_revision) AS INTEGER),
    acknowledged_at = CAST(sqlc.arg(acknowledged_at) AS INTEGER)
WHERE id = sqlc.arg(source_id)
    AND revision = sqlc.arg(source_revision)
    AND acknowledged_revision IS NULL
    AND EXISTS (
        SELECT 1
        FROM route_usage_outbox_items
        WHERE source_kind = 'registration'
            AND source_id = route_registrations.id
            AND source_revision = sqlc.arg(source_revision)
    );

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
    connection_attempts,
    policy_denials,
    capacity_denials,
    publisher_open_failures,
    successful_streams,
    connection_nanoseconds,
    ingress_bytes,
    egress_bytes,
    publisher_open_latency,
    time_to_first_publisher_byte,
    successful_connection_duration,
    visitor_network_hll,
    visitor_network_estimate,
    complete,
    finalized
) VALUES (
    sqlc.arg(route_id),
    sqlc.arg(version),
    sqlc.arg(resolution),
    sqlc.arg(bucket_start),
    sqlc.arg(revision),
    sqlc.arg(observed_through),
    sqlc.arg(connection_attempts),
    sqlc.arg(policy_denials),
    sqlc.arg(capacity_denials),
    sqlc.arg(publisher_open_failures),
    sqlc.arg(successful_streams),
    sqlc.arg(connection_nanoseconds),
    sqlc.arg(ingress_bytes),
    sqlc.arg(egress_bytes),
    sqlc.narg(publisher_open_latency),
    sqlc.narg(time_to_first_publisher_byte),
    sqlc.narg(successful_connection_duration),
    sqlc.arg(visitor_network_hll),
    sqlc.arg(visitor_network_estimate),
    sqlc.arg(complete),
    sqlc.arg(finalized)
)
ON CONFLICT (route_id, version, resolution, bucket_start) DO UPDATE SET
    revision = excluded.revision,
    observed_through = excluded.observed_through,
    connection_attempts = excluded.connection_attempts,
    policy_denials = excluded.policy_denials,
    capacity_denials = excluded.capacity_denials,
    publisher_open_failures = excluded.publisher_open_failures,
    successful_streams = excluded.successful_streams,
    connection_nanoseconds = excluded.connection_nanoseconds,
    ingress_bytes = excluded.ingress_bytes,
    egress_bytes = excluded.egress_bytes,
    publisher_open_latency = excluded.publisher_open_latency,
    time_to_first_publisher_byte = excluded.time_to_first_publisher_byte,
    successful_connection_duration = excluded.successful_connection_duration,
    visitor_network_hll = excluded.visitor_network_hll,
    visitor_network_estimate = excluded.visitor_network_estimate,
    complete = excluded.complete,
    finalized = excluded.finalized
WHERE excluded.revision >= route_usage_snapshots.revision
RETURNING id;

-- name: UpsertRouteUsageReport :execrows
INSERT INTO route_usage_reports (
    snapshot_id,
    report_id,
    revision,
    observed_through,
    connection_attempts,
    policy_denials,
    capacity_denials,
    publisher_open_failures,
    successful_streams,
    connection_nanoseconds,
    ingress_bytes,
    egress_bytes,
    publisher_open_latency,
    time_to_first_publisher_byte,
    successful_connection_duration,
    visitor_network_hll,
    visitor_network_estimate,
    complete
) VALUES (
    sqlc.arg(snapshot_id),
    coalesce(
        (SELECT report_id FROM route_usage_reports WHERE snapshot_id = sqlc.arg(snapshot_id) AND revision = sqlc.arg(revision)),
        CAST(sqlc.arg(report_id) AS TEXT)
    ),
    sqlc.arg(revision),
    sqlc.arg(observed_through),
    sqlc.arg(connection_attempts),
    sqlc.arg(policy_denials),
    sqlc.arg(capacity_denials),
    sqlc.arg(publisher_open_failures),
    sqlc.arg(successful_streams),
    sqlc.arg(connection_nanoseconds),
    sqlc.arg(ingress_bytes),
    sqlc.arg(egress_bytes),
    sqlc.narg(publisher_open_latency),
    sqlc.narg(time_to_first_publisher_byte),
    sqlc.narg(successful_connection_duration),
    sqlc.arg(visitor_network_hll),
    sqlc.arg(visitor_network_estimate),
    sqlc.arg(complete)
)
ON CONFLICT (snapshot_id) DO UPDATE SET
    report_id = CASE
        WHEN excluded.revision > route_usage_reports.revision THEN excluded.report_id
        ELSE route_usage_reports.report_id
    END,
    revision = excluded.revision,
    observed_through = excluded.observed_through,
    connection_attempts = excluded.connection_attempts,
    policy_denials = excluded.policy_denials,
    capacity_denials = excluded.capacity_denials,
    publisher_open_failures = excluded.publisher_open_failures,
    successful_streams = excluded.successful_streams,
    connection_nanoseconds = excluded.connection_nanoseconds,
    ingress_bytes = excluded.ingress_bytes,
    egress_bytes = excluded.egress_bytes,
    publisher_open_latency = excluded.publisher_open_latency,
    time_to_first_publisher_byte = excluded.time_to_first_publisher_byte,
    successful_connection_duration = excluded.successful_connection_duration,
    visitor_network_hll = excluded.visitor_network_hll,
    visitor_network_estimate = excluded.visitor_network_estimate,
    complete = excluded.complete
WHERE excluded.revision > route_usage_reports.revision OR (
    excluded.revision = route_usage_reports.revision
    AND excluded.observed_through = route_usage_reports.observed_through
    AND excluded.connection_attempts = route_usage_reports.connection_attempts
    AND excluded.policy_denials = route_usage_reports.policy_denials
    AND excluded.capacity_denials = route_usage_reports.capacity_denials
    AND excluded.publisher_open_failures = route_usage_reports.publisher_open_failures
    AND excluded.successful_streams = route_usage_reports.successful_streams
    AND excluded.connection_nanoseconds = route_usage_reports.connection_nanoseconds
    AND excluded.ingress_bytes = route_usage_reports.ingress_bytes
    AND excluded.egress_bytes = route_usage_reports.egress_bytes
    AND excluded.publisher_open_latency IS route_usage_reports.publisher_open_latency
    AND excluded.time_to_first_publisher_byte IS route_usage_reports.time_to_first_publisher_byte
    AND excluded.successful_connection_duration IS route_usage_reports.successful_connection_duration
    AND excluded.visitor_network_hll = route_usage_reports.visitor_network_hll
    AND excluded.visitor_network_estimate = route_usage_reports.visitor_network_estimate
    AND excluded.complete = route_usage_reports.complete
);

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
WHERE finalized = 0
ORDER BY bucket_start, route_id, version, resolution;

-- name: DeleteAcknowledgedRouteUsageSnapshot :execrows
DELETE FROM route_usage_snapshots
WHERE id = sqlc.arg(id)
    AND finalized = 1
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
        AND NOT (
            event.transition = 'version_started'
            AND EXISTS (
                SELECT 1
                FROM routes AS current_route
                WHERE current_route.id = event.route_id
                    AND current_route.version = event.version
                    AND current_route.status <> 'deleted'
            )
        )
        AND NOT EXISTS (
            SELECT 1
            FROM route_usage_outbox_items
            WHERE source_kind = 'lifecycle_event'
                AND source_id = event.id
        )
    ORDER BY event.occurred_at, event.id
    LIMIT sqlc.arg(batch_size)
);
