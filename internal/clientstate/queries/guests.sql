-- name: GetGuestSession :one
SELECT * FROM guest_demo_sessions WHERE server_origin = sqlc.arg(server_origin);

-- name: SaveGuestSession :exec
INSERT INTO guest_demo_sessions (
    server_origin, guest_id, access_token_ciphertext, team_id,
    membership_id, domain_id, namespace, expires_at, created_at
) VALUES (
    sqlc.arg(server_origin), sqlc.arg(guest_id), sqlc.arg(access_token_ciphertext), sqlc.arg(team_id),
    sqlc.arg(membership_id), sqlc.arg(domain_id), sqlc.arg(namespace), sqlc.arg(expires_at), sqlc.arg(created_at)
)
ON CONFLICT (server_origin) DO NOTHING;

-- name: DeleteGuestSession :exec
DELETE FROM guest_demo_sessions WHERE server_origin = sqlc.arg(server_origin);
