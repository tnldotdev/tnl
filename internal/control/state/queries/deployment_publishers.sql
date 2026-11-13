-- name: LockDeploymentPublisherEnrollment :one
SELECT * FROM control.deployment_publisher_enrollments WHERE id=sqlc.arg(id) FOR UPDATE;

-- name: FindDeploymentPublisherEnrollmentRequest :one
SELECT * FROM control.deployment_publisher_enrollments
WHERE deployment_id=sqlc.arg(deployment_id) AND create_principal_id=sqlc.arg(principal_id)::text
AND idempotency_key=sqlc.arg(idempotency_key)::text FOR UPDATE;

-- name: ListDeploymentPublisherEnrollmentServices :many
SELECT * FROM control.deployment_publisher_enrollment_services WHERE enrollment_id=sqlc.arg(enrollment_id) ORDER BY service;

-- name: DeploymentPublisherServiceAllowed :one
SELECT EXISTS(SELECT 1 FROM control.deployment_publisher_members member
JOIN control.deployment_publisher_enrollments enrollment ON enrollment.id=member.enrollment_id
WHERE member.publisher_identity_id=sqlc.arg(publisher_id) AND member.deployment_id=sqlc.arg(deployment_id)::text
AND EXISTS(SELECT 1 FROM control.deployment_publisher_enrollment_services scope
    WHERE scope.enrollment_id=enrollment.id AND scope.service=sqlc.arg(service)
    AND scope.service_id IS NOT DISTINCT FROM sqlc.narg(service_id)::text
    AND scope.public_url_id IS NOT DISTINCT FROM sqlc.narg(public_url_id)::text
    AND scope.revoked_at IS NULL AND scope.protocol=COALESCE((SELECT protocol FROM control.services WHERE id=scope.service_id),'http')))::boolean;

-- name: ListDeploymentPublisherIDs :many
SELECT member.publisher_identity_id FROM control.deployment_publisher_members member
WHERE member.deployment_id=sqlc.arg(deployment_id) AND member.publisher_identity_id COLLATE "C">sqlc.arg(after_id)::text COLLATE "C"
AND (sqlc.arg(management_grant)::text='' OR control.deployment_management_publisher_allowed(sqlc.arg(management_grant),member.publisher_identity_id))
ORDER BY member.publisher_identity_id COLLATE "C" LIMIT sqlc.arg(page_limit);

-- name: DeploymentManagementPublisherAllowed :one
SELECT control.deployment_management_publisher_allowed(sqlc.arg(grant_id)::text,sqlc.arg(publisher_id)::text)::boolean;

-- name: GetDeploymentPublisherStatus :one
SELECT sqlc.embed(member), publisher.revoked_at,
    deployment.team_id,deployment.project_key,deployment.name AS deployment_name,deployment.revision AS current_revision
FROM control.deployment_publisher_members member
JOIN control.publisher_identities publisher ON publisher.id=member.publisher_identity_id
JOIN control.deployment_publisher_enrollments enrollment ON enrollment.id=member.enrollment_id
JOIN control.deployments deployment ON deployment.id=member.deployment_id AND deployment.deleted_at IS NULL
WHERE member.deployment_id=sqlc.arg(deployment_id) AND member.publisher_identity_id=sqlc.arg(publisher_id);
