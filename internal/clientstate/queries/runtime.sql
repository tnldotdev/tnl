-- name: RuntimeSnapshot :one
SELECT snapshot_json FROM local_runtime_snapshots
WHERE project_root = sqlc.arg(project_root);

-- name: ListRuntimeSnapshots :many
SELECT project_root, snapshot_json FROM local_runtime_snapshots ORDER BY project_root;

-- name: RuntimeEvents :many
SELECT event_json FROM local_runtime_events
WHERE project_root = sqlc.arg(project_root) ORDER BY cursor;

-- name: UpsertRuntimeSnapshot :one
INSERT INTO local_runtime_snapshots (project_root, cursor, snapshot_json)
VALUES (sqlc.arg(project_root), sqlc.arg(cursor), json_set(sqlc.arg(snapshot_json), '$.cursor', CAST(sqlc.arg(cursor) AS TEXT)))
ON CONFLICT (project_root) DO UPDATE SET
    cursor = local_runtime_snapshots.cursor + 1,
    snapshot_json = json_set(excluded.snapshot_json, '$.cursor', CAST(local_runtime_snapshots.cursor + 1 AS TEXT))
RETURNING cursor;

-- name: InsertRuntimeEvent :exec
INSERT INTO local_runtime_events (project_root, cursor, event_json)
VALUES (sqlc.arg(project_root), sqlc.arg(cursor), sqlc.arg(event_json));
