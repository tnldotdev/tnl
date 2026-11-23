-- name: BindDirectoryIdentityToCheckout :exec
UPDATE local_project_identities
SET project_root=sqlc.arg(checkout_key)
WHERE local_project_identities.project_root=sqlc.arg(directory)
  AND NOT EXISTS (SELECT 1 FROM local_project_identities AS bound WHERE bound.project_root=sqlc.arg(checkout_key));

-- name: EnsureLocalProjectIdentity :one
INSERT INTO local_project_identities(project_root,source_id,worktree_id)
VALUES(sqlc.arg(project_root),sqlc.arg(source_id),sqlc.arg(worktree_id))
ON CONFLICT(project_root) DO UPDATE SET project_root=excluded.project_root
RETURNING source_id,worktree_id;
