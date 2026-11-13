-- name: LockPublisherGroupEnrollment :one
SELECT * FROM control.publisher_group_enrollments WHERE id=sqlc.arg(id) FOR UPDATE;

-- name: FindPublisherGroupEnrollmentRequest :one
SELECT * FROM control.publisher_group_enrollments
WHERE group_id=sqlc.arg(group_id) AND created_by_identity_id=sqlc.arg(actor_id)
AND idempotency_key=sqlc.arg(idempotency_key)::text FOR UPDATE;

-- name: ListPublisherGroupEnrollmentServices :many
SELECT * FROM control.publisher_group_enrollment_services WHERE enrollment_id=sqlc.arg(enrollment_id) ORDER BY service;

-- name: PublisherGroupServiceAllowed :one
SELECT EXISTS(SELECT 1 FROM control.publisher_group_members member
JOIN control.publisher_group_enrollments enrollment ON enrollment.id=member.enrollment_id
WHERE member.publisher_identity_id=sqlc.arg(publisher_id) AND member.group_id=sqlc.arg(group_id)::text
AND (NOT enrollment.scoped OR EXISTS(SELECT 1 FROM control.publisher_group_enrollment_services scope
    WHERE scope.enrollment_id=enrollment.id AND scope.service=sqlc.arg(service)
    AND scope.service_id IS NOT DISTINCT FROM sqlc.narg(service_id)::text
    AND scope.public_url_id IS NOT DISTINCT FROM sqlc.narg(public_url_id)::text
    AND scope.revoked_at IS NULL AND scope.protocol=COALESCE((SELECT protocol FROM control.services WHERE id=scope.service_id),'http'))))::boolean;

-- name: ListDeploymentPublisherIDs :many
SELECT member.publisher_identity_id FROM control.publisher_group_members member
WHERE member.group_id=sqlc.arg(group_id) AND member.publisher_identity_id COLLATE "C">sqlc.arg(after_id)::text COLLATE "C"
ORDER BY member.publisher_identity_id COLLATE "C" LIMIT sqlc.arg(page_limit);

-- name: GetDeploymentPublisherStatus :one
SELECT sqlc.embed(member), publisher.revoked_at, enrollment.scoped,
    deployment.team_id,deployment.project_key,deployment.name AS group_name,deployment.revision AS current_revision
FROM control.publisher_group_members member
JOIN control.publisher_identities publisher ON publisher.id=member.publisher_identity_id
JOIN control.publisher_group_enrollments enrollment ON enrollment.id=member.enrollment_id
JOIN control.project_publisher_groups deployment ON deployment.id=member.group_id AND deployment.deleted_at IS NULL
WHERE member.group_id=sqlc.arg(group_id) AND member.publisher_identity_id=sqlc.arg(publisher_id);
