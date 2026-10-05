-- name: CreateWorktreePreview :one
INSERT INTO control.worktree_previews (
    id, team_id, created_by_identity_id, idempotency_key, created_at
) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (team_id, created_by_identity_id, idempotency_key)
DO UPDATE SET idempotency_key = EXCLUDED.idempotency_key
RETURNING id, team_id, created_by_identity_id, created_at;

-- name: GetWorktreePreview :one
SELECT id, team_id, created_by_identity_id, created_at
FROM control.worktree_previews WHERE id = $1;

-- name: ListWorktreePreviewPublicURLs :many
SELECT public_url_id FROM control.worktree_preview_public_urls
WHERE worktree_preview_id = $1 ORDER BY public_url_id;

-- name: AddWorktreePreviewPublicURL :one
INSERT INTO control.worktree_preview_public_urls (
    worktree_preview_id, team_id, public_url_id, added_at
)
SELECT p.id, p.team_id, u.id, sqlc.arg(added_at)::timestamptz
FROM control.worktree_previews p
JOIN control.public_urls u ON u.id = sqlc.arg(public_url_id) AND u.team_id = p.team_id
WHERE p.id = sqlc.arg(worktree_preview_id)
  AND p.created_by_identity_id = sqlc.arg(identity_id)
  AND u.mutation_revision = sqlc.arg(expected_mutation_revision)
  AND u.lifecycle_state = 'enabled'
ON CONFLICT (worktree_preview_id, public_url_id) DO UPDATE SET
    added_at = control.worktree_preview_public_urls.added_at
RETURNING public_url_id;
