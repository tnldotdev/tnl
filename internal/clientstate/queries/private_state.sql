-- name: GetPublisherSigningIdentity :one
SELECT * FROM publisher_signing_identities WHERE server_origin = sqlc.arg(server_origin) AND scope = sqlc.arg(scope);

-- name: SavePublisherSigningIdentity :exec
INSERT INTO publisher_signing_identities (server_origin, scope, identity_id, public_value, stored_private, updated_at)
VALUES (sqlc.arg(server_origin), sqlc.arg(scope), sqlc.arg(identity_id), sqlc.arg(public_value), sqlc.arg(stored_private), sqlc.arg(updated_at))
ON CONFLICT (server_origin, scope) DO UPDATE SET identity_id = excluded.identity_id, public_value = excluded.public_value,
    stored_private = excluded.stored_private, updated_at = excluded.updated_at;

-- name: DeletePublisherSigningIdentity :exec
DELETE FROM publisher_signing_identities WHERE server_origin = sqlc.arg(server_origin) AND scope = sqlc.arg(scope);

-- name: GetSystemState :one
SELECT stored_value FROM system_state WHERE name = sqlc.arg(name);

-- name: SaveSystemState :exec
INSERT INTO system_state (name, stored_value, updated_at) VALUES (sqlc.arg(name), sqlc.arg(stored_value), sqlc.arg(updated_at))
ON CONFLICT (name) DO UPDATE SET stored_value = excluded.stored_value, updated_at = excluded.updated_at;

-- name: DeleteSystemState :exec
DELETE FROM system_state WHERE name = sqlc.arg(name);
