-- name: GetWorkloadSession :one
SELECT * FROM control.workload_sessions WHERE id = $1;

-- name: LockWorkloadSession :one
SELECT * FROM control.workload_sessions WHERE id = $1 FOR UPDATE;

-- name: ListWorkloadSessionServices :many
SELECT applied.service_id::text AS service_id,applied.service
FROM control.workload_sessions session
JOIN control.applied_project_services applied ON applied.team_id=session.team_id AND applied.project_key=session.project_key
WHERE session.id=sqlc.arg(session_id) AND EXISTS(SELECT 1 FROM control.workload_visit_authority(sqlc.arg(now)::timestamptz)
    WHERE session_id=session.id AND resource_kind='service' AND resource_id=applied.service_id) ORDER BY applied.service;
-- name: VisitorServiceConfiguration :one
SELECT project.team_id,project.project_key,project.configuration_ciphertext,project.storage_key_id,service.service
FROM control.applied_project_services service
JOIN control.applied_projects project ON project.team_id=service.team_id AND project.project_key=service.project_key
WHERE service.service_id=$1;
