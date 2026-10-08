-- name: NextLocalRequestNumber :one
INSERT INTO local_request_counters (primary_checkout_root, last_number)
VALUES (sqlc.arg(primary_checkout_root), 1)
ON CONFLICT (primary_checkout_root) DO UPDATE SET last_number = last_number + 1
RETURNING last_number;

-- name: InsertLocalRequest :exec
INSERT INTO local_requests (
    request_number, primary_checkout_root, tunnel_id, project_root, shared_project_root,
    service, received_at, method, path, status, duration_ms, origin, capture_mode, detail_json
) VALUES (
    sqlc.arg(request_number), sqlc.arg(primary_checkout_root), sqlc.arg(tunnel_id),
    sqlc.arg(project_root), sqlc.arg(shared_project_root), sqlc.arg(service), sqlc.arg(received_at),
    sqlc.arg(method), sqlc.arg(path), sqlc.arg(status), sqlc.arg(duration_ms), sqlc.arg(origin),
    sqlc.arg(capture_mode), sqlc.narg(detail_json)
);

-- name: DeleteExpiredLocalRequests :exec
DELETE FROM local_requests WHERE received_at < sqlc.arg(before);

-- name: PruneLocalRequestsToLimit :exec
DELETE FROM local_requests WHERE row_id NOT IN
    (SELECT row_id FROM local_requests ORDER BY received_at DESC, row_id DESC LIMIT sqlc.arg(max_rows));
