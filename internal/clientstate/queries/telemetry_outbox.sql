-- name: InsertTelemetryEvent :exec
INSERT INTO telemetry_outbox (event_id, created_at, event_json)
VALUES (sqlc.arg(event_id), sqlc.arg(created_at), sqlc.arg(event_json));

-- name: DeleteExpiredTelemetryEvents :exec
DELETE FROM telemetry_outbox WHERE created_at < sqlc.arg(before);

-- name: PruneTelemetryEventsToLimit :exec
DELETE FROM telemetry_outbox WHERE event_id NOT IN
    (SELECT event_id FROM telemetry_outbox ORDER BY created_at DESC, event_id DESC LIMIT sqlc.arg(max_events));

-- name: SelectPendingTelemetryEvents :many
SELECT event_id, event_json FROM telemetry_outbox
ORDER BY created_at, event_id LIMIT sqlc.arg(max_events);

-- name: DeleteAcknowledgedTelemetryEvents :exec
DELETE FROM telemetry_outbox WHERE event_id IN
    (SELECT value FROM json_each(CAST(sqlc.arg(event_ids) AS TEXT)));

-- name: ClearTelemetryEvents :exec
DELETE FROM telemetry_outbox;
