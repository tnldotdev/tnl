-- name: GetWorkloadSession :one
SELECT * FROM control.workload_sessions WHERE id = $1;

-- name: LockWorkloadSession :one
SELECT * FROM control.workload_sessions WHERE id = $1 FOR UPDATE;

-- name: ListWorkloadSessionServices :many
SELECT rights.service_id,rights.service FROM control.workload_session_services rights
JOIN control.workload_session_machines source ON source.session_id=rights.workload_session_id
JOIN control.machine_workload_permissions permission ON permission.id=source.permission_id
JOIN control.environments environment ON environment.id=source.environment_id
JOIN control.applied_project_services binding ON binding.service_id=rights.service_id AND binding.group_id=environment.group_id
JOIN control.services service ON service.id=rights.service_id AND service.enabled AND service.deleted_at IS NULL
    AND service.protocol=source.expected_protocols->>rights.service
WHERE rights.workload_session_id=$1 AND rights.service=ANY(permission.services) ORDER BY rights.service;
-- name: VisitorServiceConfiguration :one
SELECT service.service,service.group_id,COALESCE(publisher_group.environment_id,environment.id,'')::text AS environment_id
FROM control.applied_project_services service
LEFT JOIN control.project_publisher_groups publisher_group ON publisher_group.id=service.group_id
LEFT JOIN control.environments environment ON environment.group_id=publisher_group.id
WHERE service.service_id=$1;
