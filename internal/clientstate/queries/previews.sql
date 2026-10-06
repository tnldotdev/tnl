-- name: GetPreviewID :one
SELECT preview_id FROM previews
WHERE server_origin = sqlc.arg(server_origin)
  AND team_id = sqlc.arg(team_id)
  AND project_root = sqlc.arg(project_root);

-- name: SavePreviewID :exec
INSERT INTO previews (server_origin, team_id, project_root, preview_id, updated_at)
VALUES (sqlc.arg(server_origin), sqlc.arg(team_id), sqlc.arg(project_root), sqlc.arg(preview_id), sqlc.arg(updated_at))
ON CONFLICT (server_origin, team_id, project_root) DO UPDATE SET
    preview_id = excluded.preview_id,
    updated_at = excluded.updated_at;
