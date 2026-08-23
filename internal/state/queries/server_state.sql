-- name: GetServerState :one
SELECT value FROM server_state WHERE state_key = ?;

-- name: InsertServerState :execrows
INSERT INTO server_state (state_key, value)
VALUES (?, ?)
ON CONFLICT (state_key) DO NOTHING;

-- name: PutServerState :exec
INSERT INTO server_state (state_key, value)
VALUES (?, ?)
ON CONFLICT (state_key) DO UPDATE SET value = excluded.value;

-- name: DeleteServerState :exec
DELETE FROM server_state WHERE state_key = ?;
