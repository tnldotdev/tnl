-- name: LockEnvironmentPublisherAssignment :one
SELECT * FROM control.project_publisher_groups
WHERE id=sqlc.arg(group_id) AND environment_id=sqlc.arg(environment_id)
    AND team_id=sqlc.arg(team_id) AND project_key=sqlc.arg(project_key) AND deleted_at IS NULL
FOR UPDATE;

-- name: LockEnvironmentPublisherService :one
SELECT binding.* FROM control.applied_project_services binding
WHERE binding.team_id=sqlc.arg(team_id) AND binding.project_key=sqlc.arg(project_key)
    AND binding.group_id=sqlc.arg(group_id) AND binding.service_id=sqlc.arg(service_id)
FOR UPDATE;

-- name: LockEnvironmentPublisherMember :one
SELECT member.* FROM control.publisher_group_members member
JOIN control.publisher_identities publisher ON publisher.id=member.publisher_identity_id
JOIN control.publisher_identity_keys signing_key ON signing_key.id=member.key_id
    AND signing_key.publisher_identity_id=publisher.id AND signing_key.retired_at IS NULL
WHERE member.publisher_identity_id=sqlc.arg(publisher_identity_id) AND member.group_id=sqlc.arg(group_id)
    AND publisher.team_id=sqlc.arg(team_id) AND publisher.kind='installed' AND publisher.ownership='team'
    AND control.active_publisher(publisher.id,sqlc.arg(now))
FOR UPDATE OF member,publisher,signing_key;

-- name: LockEnvironmentPublisherGrantMapping :one
SELECT grant_record.* FROM control.publisher_group_service_grants mapping
JOIN control.publisher_grants grant_record ON grant_record.id=mapping.grant_id
    AND grant_record.publisher_identity_id=mapping.publisher_identity_id
WHERE mapping.team_id=sqlc.arg(team_id) AND mapping.project_key=sqlc.arg(project_key)
    AND mapping.publisher_identity_id=sqlc.arg(publisher_identity_id) AND mapping.service=sqlc.arg(service)
FOR UPDATE OF mapping,grant_record;

-- name: SetEnvironmentPublisherGrantMapping :execrows
INSERT INTO control.publisher_group_service_grants(team_id,project_key,publisher_identity_id,service,grant_id)
VALUES(sqlc.arg(team_id),sqlc.arg(project_key),sqlc.arg(publisher_identity_id),sqlc.arg(service),sqlc.arg(grant_id))
ON CONFLICT(publisher_identity_id,team_id,project_key,service) DO UPDATE SET grant_id=EXCLUDED.grant_id
WHERE control.publisher_group_service_grants.grant_id=sqlc.narg(previous_grant_id)::text;

-- name: ReadEnvironmentPublisherGrantRequest :one
SELECT * FROM control.environment_publisher_grant_requests
WHERE team_id=sqlc.arg(team_id) AND project_key=sqlc.arg(project_key)
    AND environment_id=sqlc.arg(environment_id) AND idempotency_key=sqlc.arg(idempotency_key);

-- name: InsertEnvironmentPublisherGrantRequest :exec
INSERT INTO control.environment_publisher_grant_requests(team_id,project_key,environment_id,idempotency_key,
    publisher_identity_id,service_id,request_digest,grant_id,created_by_identity_id,created_at)
VALUES(sqlc.arg(team_id),sqlc.arg(project_key),sqlc.arg(environment_id),sqlc.arg(idempotency_key),
    sqlc.arg(publisher_identity_id),sqlc.arg(service_id),sqlc.arg(request_digest),sqlc.arg(grant_id),sqlc.arg(created_by_identity_id),sqlc.arg(now));

-- name: InvalidateEnvironmentPublisherMember :exec
UPDATE control.publisher_group_members SET healthy=false,acknowledged_at=NULL
WHERE publisher_identity_id=sqlc.arg(publisher_identity_id) AND group_id=sqlc.arg(group_id);

-- name: LockEnvironmentPublisherManagerSession :one
SELECT session.id,session.identity_id,session.access_token_digest,session.access_expires_at,session.refresh_expires_at
FROM control.control_sessions session
JOIN control.identities person ON person.id=session.identity_id AND person.disabled_at IS NULL
WHERE session.access_token_id=sqlc.arg(access_token_id) AND session.revoked_at IS NULL
FOR SHARE OF session;
