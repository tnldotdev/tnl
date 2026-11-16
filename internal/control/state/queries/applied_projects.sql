-- name: LockAppliedProject :one
SELECT * FROM control.applied_projects WHERE team_id=sqlc.arg(team_id) AND project_key=sqlc.arg(project_key) FOR UPDATE;

-- name: ListDiscoverableProjects :many
SELECT project_key, project_label, revision, updated_at FROM control.applied_projects
WHERE team_id=sqlc.arg(team_id) AND project_key>sqlc.arg(after_key) AND retired_at IS NULL
ORDER BY project_key LIMIT 101;

-- name: ListDiscoverablePreviews :many
SELECT id, created_at FROM control.previews
WHERE team_id=sqlc.arg(team_id) AND created_by_identity_id=sqlc.arg(created_by_identity_id)
    AND id>sqlc.arg(after_id)
ORDER BY id LIMIT 101;
-- name: GetDeploymentServiceConfiguration :one
SELECT sqlc.embed(deployment),binding.service FROM control.applied_project_services binding
JOIN control.project_publisher_groups deployment ON deployment.id=binding.group_id AND deployment.deleted_at IS NULL
WHERE binding.service_id=sqlc.arg(service_id);

-- name: ListProjectServiceDeclarations :many
SELECT name,protocol FROM control.project_services WHERE team_id=sqlc.arg(team_id) AND project_key=sqlc.arg(project_key) ORDER BY name;

-- name: SaveProjectServiceDeclaration :exec
INSERT INTO control.project_services(team_id,project_key,name,protocol)
VALUES(sqlc.arg(team_id),sqlc.arg(project_key),sqlc.arg(name),sqlc.arg(protocol))
ON CONFLICT(team_id,project_key,name) DO UPDATE SET protocol=EXCLUDED.protocol;

-- name: RemoveProjectServiceDeclarations :exec
DELETE FROM control.project_services declaration
WHERE declaration.team_id=sqlc.arg(team_id) AND declaration.project_key=sqlc.arg(project_key) AND NOT(declaration.name=ANY(sqlc.arg(names)::text[]))
AND NOT EXISTS(SELECT 1 FROM control.applied_project_services binding WHERE binding.team_id=declaration.team_id AND binding.project_key=declaration.project_key AND binding.service=declaration.name);

-- name: ServiceNamespaceOwnsHostname :one
SELECT (EXISTS(SELECT 1 FROM control.service_namespace_claims
    WHERE sqlc.arg(hostname)::text=namespace OR right(sqlc.arg(hostname)::text,length(namespace)+1)='.'||namespace)
    OR EXISTS(SELECT 1 FROM control.service_endpoints WHERE hostname=sqlc.arg(hostname)))::boolean;

-- name: ListAppliedProjectServices :many
SELECT * FROM control.applied_project_services WHERE team_id=sqlc.arg(team_id) AND project_key=sqlc.arg(project_key) ORDER BY group_id,service;

-- name: ListPublisherGroupServices :many
SELECT * FROM control.applied_project_services WHERE group_id=sqlc.arg(group_id)::text ORDER BY service;

-- name: ListProjectPublisherGroups :many
SELECT * FROM control.project_publisher_groups WHERE team_id=sqlc.arg(team_id) AND project_key=sqlc.arg(project_key) AND deleted_at IS NULL ORDER BY name;

-- name: LockProjectPublisherGroup :one
SELECT * FROM control.project_publisher_groups WHERE id=sqlc.arg(id) AND deleted_at IS NULL FOR UPDATE;

-- name: LockDeployment :one
SELECT g.* FROM control.project_publisher_groups g
WHERE g.team_id=sqlc.arg(team_id) AND g.project_key=sqlc.arg(project_key) AND g.deleted_at IS NULL
AND (g.id=sqlc.arg(selector) OR EXISTS(SELECT 1 FROM control.publisher_group_names alias WHERE alias.group_id=g.id AND alias.name=sqlc.arg(selector))) FOR UPDATE;

-- name: ListDeployments :many
SELECT * FROM control.project_publisher_groups
WHERE team_id=sqlc.arg(team_id) AND project_key=sqlc.arg(project_key) AND deleted_at IS NULL
AND id COLLATE "C">sqlc.arg(after_id)::text COLLATE "C" ORDER BY id COLLATE "C" LIMIT sqlc.arg(page_limit);

-- name: AcknowledgePublisherGroupConfiguration :exec
UPDATE control.publisher_group_members
SET observed_revision=sqlc.arg(revision), healthy=sqlc.arg(healthy), acknowledged_at=sqlc.arg(acknowledged_at)
WHERE publisher_identity_id=sqlc.arg(publisher_identity_id);

-- name: InvalidatePublisherGroupRuntimeHealth :exec
UPDATE control.publisher_group_members
SET healthy=false, acknowledged_at=NULL
WHERE publisher_identity_id=sqlc.arg(publisher_identity_id);

-- name: ListPublisherGroupMemberStatus :many
SELECT g.id AS group_id, g.name AS group_name, m.publisher_identity_id, m.key_id,
    m.observed_revision, g.revision AS current_revision, m.acknowledged_at,
    (m.healthy AND m.lease_expires_at>sqlc.arg(now) AND m.observed_revision=g.revision)::boolean AS healthy,
    m.lease_expires_at
FROM control.project_publisher_groups g
JOIN control.publisher_group_members m ON m.group_id=g.id
JOIN control.publisher_identities i ON i.id=m.publisher_identity_id
WHERE g.team_id=sqlc.arg(team_id) AND g.project_key=sqlc.arg(project_key)
    AND g.deleted_at IS NULL AND i.revoked_at IS NULL
ORDER BY g.name,m.publisher_identity_id;

-- name: GetLocalProjectService :one
SELECT local.source_fingerprint, sqlc.embed(s)
FROM control.local_project_services local
JOIN control.services s ON s.id=local.service_id AND s.team_id=local.team_id
WHERE local.team_id=sqlc.arg(team_id) AND local.project_key=sqlc.arg(project_key)
    AND local.service=sqlc.arg(service) AND local.worktree_key=sqlc.arg(worktree_key);
