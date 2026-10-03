-- name: GetGuestSession :one
SELECT * FROM guest_sessions WHERE server_origin = sqlc.arg(server_origin);

-- name: SaveGuestSession :exec
INSERT INTO guest_sessions (
    server_origin, guest_id, stored_access_token, team_id,
    membership_id, domain_id, namespace, source_ip, created_at
) VALUES (
    sqlc.arg(server_origin), sqlc.arg(guest_id), sqlc.arg(stored_access_token), sqlc.arg(team_id),
    sqlc.arg(membership_id), sqlc.arg(domain_id), sqlc.arg(namespace), sqlc.arg(source_ip), sqlc.arg(created_at)
)
ON CONFLICT (server_origin) DO NOTHING;

-- name: DeleteGuestSession :exec
DELETE FROM guest_sessions WHERE server_origin = sqlc.arg(server_origin);
