-- name: EnsureLocalProjectIdentity :one
INSERT INTO local_project_identities(project_root,source_id,worktree_id)
VALUES(sqlc.arg(project_root),sqlc.arg(source_id),sqlc.arg(worktree_id))
ON CONFLICT(project_root) DO UPDATE SET project_root=excluded.project_root
RETURNING source_id,worktree_id;
