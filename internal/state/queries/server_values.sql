-- name: GetServerValue :one
SELECT value FROM server_values WHERE key = ?;

-- name: InsertServerValue :execrows
INSERT INTO server_values (key, value)
VALUES (?, ?)
ON CONFLICT (key) DO NOTHING;

-- name: PutServerValue :exec
INSERT INTO server_values (key, value)
VALUES (?, ?)
ON CONFLICT (key) DO UPDATE SET value = excluded.value;

-- name: DeleteServerValue :exec
DELETE FROM server_values WHERE key = ?;
