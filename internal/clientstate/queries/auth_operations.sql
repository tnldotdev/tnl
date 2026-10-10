-- name: InsertAuthOperation :exec
INSERT INTO auth_operations (server_origin, operation_id, phase, revision, public_json, stored_private, updated_at)
VALUES (?, ?, ?, 1, ?, ?, ?);

-- name: GetAuthOperation :one
SELECT * FROM auth_operations WHERE server_origin = ? AND operation_id = ?;

-- name: GetActiveAuthOperation :one
SELECT * FROM auth_operations
WHERE server_origin = ? AND phase IN ('pending', 'redeeming', 'credential_received', 'exchanging', 'issued')
ORDER BY updated_at DESC LIMIT 1;

-- name: UpdateAuthOperation :execrows
UPDATE auth_operations SET phase = sqlc.arg(phase), revision = revision + 1,
    public_json = sqlc.arg(public_json), stored_private = sqlc.arg(stored_private), updated_at = sqlc.arg(updated_at)
WHERE server_origin = sqlc.arg(server_origin) AND operation_id = sqlc.arg(operation_id) AND revision = sqlc.arg(expected_revision);

-- name: FenceAuthOperations :exec
UPDATE auth_operations SET phase = 'cancelled', revision = revision + 1,
    stored_private = CASE WHEN phase = 'issued' THEN stored_private ELSE X'' END, updated_at = ?
WHERE server_origin = ? AND phase NOT IN ('cancelled', 'denied', 'expired', 'recovery_required');

-- name: ListCancelledAuthCredentials :many
SELECT * FROM auth_operations WHERE server_origin = ? AND phase = 'cancelled' AND length(stored_private) > 0;
