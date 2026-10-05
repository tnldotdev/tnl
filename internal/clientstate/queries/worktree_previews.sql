-- name: GetWorktreePreviewID :one
SELECT worktree_preview_id FROM worktree_previews
WHERE server_origin = sqlc.arg(server_origin)
  AND team_id = sqlc.arg(team_id)
  AND project_root = sqlc.arg(project_root);

-- name: SaveWorktreePreviewID :exec
INSERT INTO worktree_previews (server_origin, team_id, project_root, worktree_preview_id, updated_at)
VALUES (sqlc.arg(server_origin), sqlc.arg(team_id), sqlc.arg(project_root), sqlc.arg(worktree_preview_id), sqlc.arg(updated_at))
ON CONFLICT (server_origin, team_id, project_root) DO UPDATE SET
    worktree_preview_id = excluded.worktree_preview_id,
    updated_at = excluded.updated_at;
