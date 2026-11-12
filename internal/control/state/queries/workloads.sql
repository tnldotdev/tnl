-- name: GetWorkloadSession :one
SELECT * FROM control.workload_sessions WHERE id = $1;

-- name: LockWorkloadSession :one
SELECT * FROM control.workload_sessions WHERE id = $1 FOR UPDATE;

-- name: ListWorkloadSessionServices :many
SELECT service_id,service FROM control.workload_session_services WHERE workload_session_id=$1 ORDER BY service;
-- name: VisitorServiceConfiguration :one
SELECT project.team_id,project.project_key,project.configuration_ciphertext,project.storage_key_id,service.service,service.group_id,COALESCE(publisher_group.environment_id,environment.id,'')::text AS environment_id
FROM control.applied_project_services service
JOIN control.applied_projects project ON project.team_id=service.team_id AND project.project_key=service.project_key
LEFT JOIN control.project_publisher_groups publisher_group ON publisher_group.id=service.group_id
LEFT JOIN control.environments environment ON environment.group_id=publisher_group.id
WHERE service.service_id=$1;
