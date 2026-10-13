-- name: RuntimeSnapshot :one
SELECT snapshot_json FROM local_runtime_snapshots
WHERE project_root = sqlc.arg(project_root);

-- name: ListRuntimeSnapshots :many
SELECT project_root, snapshot_json FROM local_runtime_snapshots ORDER BY project_root;

-- name: RuntimeEvents :many
SELECT event_json FROM local_runtime_events
WHERE project_root = sqlc.arg(project_root) ORDER BY cursor;

-- name: RuntimeEventSizes :many
SELECT cursor, length(event_json) AS size FROM local_runtime_events
WHERE project_root = sqlc.arg(project_root) ORDER BY cursor DESC LIMIT 2048;

-- name: UpsertRuntimeSnapshot :exec
INSERT INTO local_runtime_snapshots (project_root, cursor, snapshot_json)
VALUES (sqlc.arg(project_root), sqlc.arg(cursor), sqlc.arg(snapshot_json))
ON CONFLICT (project_root) DO UPDATE SET
    cursor = excluded.cursor,
    snapshot_json = excluded.snapshot_json
WHERE local_runtime_snapshots.cursor < excluded.cursor;

-- name: InsertRuntimeEvent :exec
INSERT INTO local_runtime_events (project_root, cursor, event_json)
VALUES (sqlc.arg(project_root), sqlc.arg(cursor), sqlc.arg(event_json));

-- name: PruneRuntimeEvents :exec
DELETE FROM local_runtime_events
WHERE project_root = sqlc.arg(project_root) AND cursor < sqlc.arg(oldest_cursor);
