-- name: LockAppliedProject :one
SELECT * FROM control.applied_projects WHERE team_id=sqlc.arg(team_id) AND project_key=sqlc.arg(project_key) FOR UPDATE;

-- name: ManagedNamespaceOwnsHostname :one
SELECT (EXISTS(SELECT 1 FROM control.managed_namespace_claims
    WHERE sqlc.arg(hostname)::text=namespace OR right(sqlc.arg(hostname)::text,length(namespace)+1)='.'||namespace)
    OR EXISTS(SELECT 1 FROM control.managed_service_endpoints WHERE hostname=sqlc.arg(hostname)))::boolean;

-- name: ListAppliedProjectServices :many
SELECT * FROM control.applied_project_services WHERE team_id=sqlc.arg(team_id) AND project_key=sqlc.arg(project_key) ORDER BY service;

-- name: ListProjectPublisherGroups :many
SELECT * FROM control.project_publisher_groups WHERE team_id=sqlc.arg(team_id) AND project_key=sqlc.arg(project_key) AND deleted_at IS NULL ORDER BY name;

-- name: ListPublisherGroupServiceGrants :many
SELECT * FROM control.publisher_group_service_grants WHERE publisher_identity_id=sqlc.arg(publisher_identity_id) ORDER BY service;

-- name: GetLocalProjectPrivateService :one
SELECT local.source_fingerprint, sqlc.embed(s)
FROM control.local_project_services local
JOIN control.private_services s ON s.id=local.private_service_id AND s.team_id=local.team_id
WHERE local.team_id=sqlc.arg(team_id) AND local.project_key=sqlc.arg(project_key)
    AND local.service=sqlc.arg(service) AND local.worktree_key=sqlc.arg(worktree_key);
