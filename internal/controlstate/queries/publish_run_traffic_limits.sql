-- name: InsertPublishRunTrafficLimits :exec
INSERT INTO control.publish_run_traffic_limits (publish_run_id, limits)
VALUES (sqlc.arg(publish_run_id), sqlc.arg(limits)::text::jsonb);

-- name: GetPublishRunTrafficLimits :one
SELECT limits
FROM control.publish_run_traffic_limits
WHERE publish_run_id = sqlc.arg(publish_run_id);
