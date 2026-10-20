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

-- name: AcknowledgePublisherGroupConfiguration :exec
UPDATE control.publisher_group_members
SET observed_revision=sqlc.arg(revision), healthy=sqlc.arg(healthy), acknowledged_at=sqlc.arg(acknowledged_at)
WHERE publisher_identity_id=sqlc.arg(publisher_identity_id);

-- name: ListPublisherGroupMemberStatus :many
SELECT g.id AS group_id, g.name AS group_name, m.publisher_identity_id, m.key_id,
    m.observed_revision, p.revision AS current_revision, m.acknowledged_at,
    (m.healthy AND m.lease_expires_at>sqlc.arg(now) AND m.observed_revision=p.revision)::boolean AS healthy,
    m.lease_expires_at
FROM control.project_publisher_groups g
JOIN control.publisher_group_members m ON m.group_id=g.id
JOIN control.publisher_identities i ON i.id=m.publisher_identity_id
JOIN control.applied_projects p ON p.team_id=g.team_id AND p.project_key=g.project_key
WHERE g.team_id=sqlc.arg(team_id) AND g.project_key=sqlc.arg(project_key)
    AND g.deleted_at IS NULL AND i.revoked_at IS NULL
ORDER BY g.name,m.publisher_identity_id;

-- name: ListPublisherGroupServiceGrants :many
SELECT * FROM control.publisher_group_service_grants WHERE publisher_identity_id=sqlc.arg(publisher_identity_id) ORDER BY service;

-- name: GetLocalProjectPrivateService :one
SELECT local.source_fingerprint, sqlc.embed(s)
FROM control.local_project_services local
JOIN control.private_services s ON s.id=local.private_service_id AND s.team_id=local.team_id
WHERE local.team_id=sqlc.arg(team_id) AND local.project_key=sqlc.arg(project_key)
    AND local.service=sqlc.arg(service) AND local.worktree_key=sqlc.arg(worktree_key);
