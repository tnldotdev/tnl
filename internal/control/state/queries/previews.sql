-- name: CreatePreview :one
INSERT INTO control.previews (
    id, team_id, created_by_identity_id, idempotency_key, created_at
) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (team_id, created_by_identity_id, idempotency_key)
DO UPDATE SET idempotency_key = EXCLUDED.idempotency_key
RETURNING id, schema_version, team_id, guest_id, created_by_identity_id, created_at, team_access_enabled;

-- name: GetPreview :one
SELECT id, schema_version, team_id, guest_id, created_by_identity_id, created_at, team_access_enabled, demo_service_run_id
FROM control.previews WHERE id = $1;

-- name: LockPreviewForTeamAccess :one
SELECT id, team_id, guest_id, created_by_identity_id, team_access_enabled, demo_service_run_id
FROM control.previews WHERE id = $1 FOR NO KEY UPDATE;

-- name: SetPreviewTeamAccess :exec
UPDATE control.previews SET team_access_enabled = sqlc.arg(enabled)
WHERE id = sqlc.arg(preview_id);

-- name: OtherPreviewForTeamAccess :one
SELECT other.preview_id FROM control.preview_services AS other
WHERE other.service_id = sqlc.arg(service_id)
  AND other.preview_id <> sqlc.arg(preview_id) LIMIT 1;

-- name: OtherTeamAccessForService :one
SELECT p.id FROM control.previews AS p
JOIN control.preview_services AS included ON included.preview_id = p.id
WHERE included.service_id = sqlc.arg(service_id)
  AND p.id <> sqlc.arg(preview_id)
  AND p.team_access_enabled = true LIMIT 1;

-- name: ListPreviewServices :many
SELECT service_id FROM control.preview_services
WHERE preview_id = $1 ORDER BY service_id;

-- name: AddPreviewService :one
INSERT INTO control.preview_services (
    preview_id, team_id, service_id, added_at
)
SELECT p.id, p.team_id, u.id, sqlc.arg(added_at)::timestamptz
FROM control.previews p
JOIN control.services u ON u.id = sqlc.arg(service_id) AND u.team_id = p.team_id
WHERE p.id = sqlc.arg(preview_id)
  AND p.created_by_identity_id = sqlc.arg(identity_id)
  AND u.enabled AND u.deleted_at IS NULL AND u.protocol='http'
ON CONFLICT (preview_id, service_id) DO UPDATE SET
    added_at = control.preview_services.added_at
RETURNING service_id;
