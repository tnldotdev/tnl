-- name: GetWorkloadSession :one
SELECT * FROM control.workload_sessions WHERE id = $1;

-- name: ListWorkloadSessionServices :many
SELECT private_service_id,service FROM control.workload_session_services WHERE workload_session_id=$1 ORDER BY service;
