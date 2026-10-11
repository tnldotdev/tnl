-- name: NextInspectionNumber :one
INSERT INTO local_inspection_counters (primary_checkout_root, last_number)
VALUES (sqlc.arg(primary_checkout_root), 1)
ON CONFLICT (primary_checkout_root) DO UPDATE SET last_number = last_number + 1
RETURNING last_number;

-- name: InsertInspection :exec
INSERT INTO local_inspections (
    number, primary_checkout_root, tunnel_id, project_root, shared_project_root,
    service, service_protocol, received_at, expires_at, stored_bytes,
    method, path, status, duration_ms, origin, capture_mode, detail_json,
    database_operation, database_result, sql_state, database_rows, database_result_sets, mysql_error_code
) VALUES (
    sqlc.arg(number), sqlc.arg(primary_checkout_root), sqlc.arg(tunnel_id),
    sqlc.arg(project_root), sqlc.arg(shared_project_root), sqlc.arg(service), sqlc.arg(service_protocol),
    sqlc.arg(received_at), sqlc.arg(expires_at), sqlc.arg(stored_bytes),
    sqlc.arg(method), sqlc.arg(path), sqlc.arg(status), sqlc.arg(duration_ms), sqlc.arg(origin),
    sqlc.arg(capture_mode), sqlc.narg(detail_json), sqlc.arg(database_operation), sqlc.arg(database_result),
    sqlc.arg(sql_state), sqlc.arg(database_rows), sqlc.arg(database_result_sets), sqlc.arg(mysql_error_code)
);

-- name: DeleteExpiredInspections :exec
DELETE FROM local_inspections WHERE expires_at <= sqlc.arg(now);
