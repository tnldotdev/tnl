-- name: EnsureRuntimeProject :exec
INSERT INTO project_journals (project_root) VALUES (sqlc.arg(project_root)) ON CONFLICT DO NOTHING;

-- name: GetRuntimeProject :one
SELECT * FROM project_journals WHERE project_root = sqlc.arg(project_root);

-- name: ListRuntimeProjects :many
SELECT project_root FROM project_journals ORDER BY project_root;

-- name: AdvanceRuntimeProject :one
UPDATE project_journals SET last_sequence = last_sequence + 1, last_observed_at = sqlc.arg(now)
WHERE project_root = sqlc.arg(project_root)
RETURNING *;

-- name: SetRuntimeServices :exec
UPDATE project_journals SET app_services_json = sqlc.arg(services_json), last_app_sequence = last_sequence
WHERE project_root = sqlc.arg(project_root);

-- name: InsertRuntimeEvent :exec
INSERT INTO project_events (project_root, sequence, event_type, occurred_at, payload_json, stored_bytes)
VALUES (sqlc.arg(project_root), sqlc.arg(sequence), sqlc.arg(event_type), sqlc.arg(created_at), sqlc.arg(payload), 1);

-- name: OldestRuntimeEvent :one
SELECT sequence FROM project_events WHERE project_root = sqlc.arg(project_root) ORDER BY sequence LIMIT 1;

-- name: ListRuntimeEvents :many
SELECT * FROM project_events
WHERE project_root = sqlc.arg(project_root) AND sequence > sqlc.arg(after)
ORDER BY sequence;

-- name: ListKnownProjectURLs :many
SELECT public_url_id FROM project_url_inventory
WHERE project_root = sqlc.arg(project_root) AND server_origin = sqlc.arg(server_origin)
ORDER BY last_seen_at DESC, public_url_id LIMIT 256;
