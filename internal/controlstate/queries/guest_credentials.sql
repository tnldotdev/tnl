-- name: EnsureGuestPrincipal :one
INSERT INTO control.identities(id, kind, display_name, administrator, created_at, updated_at)
SELECT guest.id, 'authority', guest.id, false, sqlc.arg(created_at), sqlc.arg(created_at)
FROM control.guest_trials AS guest WHERE guest.id = sqlc.arg(identity_id)
ON CONFLICT (id) DO UPDATE SET updated_at = GREATEST(control.identities.updated_at, EXCLUDED.updated_at)
WHERE control.identities.kind = 'authority' AND control.identities.disabled_at IS NULL
RETURNING *;

-- name: EnsureGuestRetryMasterKey :one
INSERT INTO control.runtime_secret(id, guest_retry_master_key_ciphertext, guest_retry_master_key_storage_key_id, created_at)
VALUES (1, sqlc.arg(ciphertext), sqlc.arg(key_id), sqlc.arg(created_at))
ON CONFLICT (id) DO UPDATE SET id = EXCLUDED.id
RETURNING guest_retry_master_key_ciphertext, guest_retry_master_key_storage_key_id;
