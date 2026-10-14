-- name: SavePublisherJob :exec
INSERT INTO publisher_jobs (public_url_id, server_origin, target, service_protocol, stored_identity, created_at)
VALUES (sqlc.arg(public_url_id), sqlc.arg(server_origin), sqlc.arg(target), sqlc.arg(service_protocol), sqlc.arg(stored_identity), sqlc.arg(created_at));

-- name: ListPublisherJobs :many
SELECT public_url_id, server_origin, target, service_protocol, stored_identity
FROM publisher_jobs
ORDER BY server_origin, public_url_id;

-- name: DeletePublisherJob :execrows
DELETE FROM publisher_jobs WHERE public_url_id = sqlc.arg(public_url_id);
