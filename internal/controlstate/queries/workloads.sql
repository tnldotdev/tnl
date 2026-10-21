-- name: GetWorkloadSession :one
SELECT * FROM control.workload_sessions WHERE id = $1;

-- name: ListWorkloadSessionServices :many
SELECT private_service_id,service FROM control.workload_session_services WHERE workload_session_id=$1 ORDER BY service;
-- name: VisitorServiceConfiguration :one
SELECT project.team_id,project.project_key,project.configuration_ciphertext,project.storage_key_id,service.service
FROM control.applied_project_services service
JOIN control.applied_projects project ON project.team_id=service.team_id AND project.project_key=service.project_key
WHERE service.private_service_id=$1;
