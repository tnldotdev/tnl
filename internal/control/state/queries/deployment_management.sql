-- name: FindDeploymentManagementRequest :one
SELECT sqlc.embed(approval), grant_record.publisher_identity_id, grant_record.expires_at
FROM control.deployment_management_grants approval
JOIN control.publisher_grants grant_record ON grant_record.id=approval.grant_id
WHERE approval.team_id=sqlc.arg(team_id) AND approval.project_key=sqlc.arg(project_key)
AND approval.created_by_identity_id=sqlc.arg(actor_id) AND approval.idempotency_key=sqlc.arg(idempotency_key);

-- name: GetDeploymentManagementGrant :one
SELECT * FROM control.deployment_management_grants WHERE grant_id=sqlc.arg(grant_id);

-- name: ListDeploymentManagementServices :many
SELECT approval.* FROM control.deployment_management_services approval
JOIN control.project_services declaration ON declaration.team_id=approval.team_id
AND declaration.project_key=approval.project_key AND declaration.name=approval.service AND declaration.protocol=approval.protocol
WHERE approval.grant_id=sqlc.arg(grant_id) AND approval.revoked_at IS NULL ORDER BY approval.service;

-- name: ListDeploymentManagementDeployments :many
SELECT deployment_id FROM control.deployment_management_deployments WHERE grant_id=sqlc.arg(grant_id) ORDER BY deployment_id;
