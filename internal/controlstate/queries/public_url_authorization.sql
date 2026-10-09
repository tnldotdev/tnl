-- name: ListAuthorizedPublicURLsData :many
SELECT routes.*, COALESCE((SELECT p.purpose FROM control.public_url_purposes AS p
 WHERE p.public_url_id = routes.id), 'unknown')::text AS purpose,
 COALESCE((SELECT sessions.id FROM control.publish_runs AS sessions
 WHERE sessions.public_url_id = routes.id AND sessions.closed_at IS NULL), '')::text AS open_publish_run_id
FROM control.public_urls AS routes
WHERE routes.team_id = sqlc.arg(team_id) AND routes.lifecycle_state <> 'deleted'
 AND (sqlc.narg(cursor)::text IS NULL OR routes.id > sqlc.narg(cursor))
ORDER BY routes.id LIMIT 101;

-- name: GetPublicURLForAuthorizationData :one
SELECT routes.*, COALESCE((SELECT p.purpose FROM control.public_url_purposes AS p
 WHERE p.public_url_id = routes.id), 'unknown')::text AS purpose,
 COALESCE((SELECT sessions.id FROM control.publish_runs AS sessions
 WHERE sessions.public_url_id = routes.id AND sessions.closed_at IS NULL), '')::text AS open_publish_run_id,
 COALESCE((SELECT sessions.publish_run_number FROM control.publish_runs AS sessions
 WHERE sessions.public_url_id = routes.id AND sessions.idempotency_key = sqlc.arg(publish_run_idempotency_key)), routes.next_publish_run_number)::bigint AS authorization_publish_run_number
FROM control.public_urls AS routes
WHERE routes.id = sqlc.arg(public_url_id) AND routes.lifecycle_state <> 'deleted';

-- name: GetAuthorizedPublicURLByHostname :one
SELECT routes.*, COALESCE((SELECT p.purpose FROM control.public_url_purposes AS p
 WHERE p.public_url_id = routes.id), 'unknown')::text AS purpose,
 COALESCE((SELECT sessions.id FROM control.publish_runs AS sessions
 WHERE sessions.public_url_id = routes.id AND sessions.closed_at IS NULL), '')::text AS open_publish_run_id
FROM control.public_urls AS routes
WHERE routes.team_id = sqlc.arg(team_id) AND routes.canonical_hostname = sqlc.arg(canonical_hostname)
 AND routes.lifecycle_state <> 'deleted';
