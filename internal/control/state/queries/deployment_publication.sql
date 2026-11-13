-- name: DeploymentPublicationAllowed :one
-- callers validate the live identity/grant and hold the publication parent first.
-- saved URL approval cannot authorize allocations or sibling private services.
SELECT EXISTS (
    SELECT 1 FROM control.deployment_management_grants approval
    JOIN control.project_publisher_groups deployment ON deployment.team_id=approval.team_id
        AND deployment.project_key=approval.project_key AND deployment.deleted_at IS NULL
    JOIN control.public_urls url ON url.id=sqlc.arg(public_url_id) AND url.team_id=approval.team_id
        AND url.lifecycle_state='enabled' AND url.service_protocol='http'
    JOIN control.domains domain ON domain.id=url.domain_id AND domain.state='ready'
        AND domain.released_at IS NULL AND (domain.kind='managed' OR domain.team_id=approval.team_id)
    WHERE approval.grant_id=sqlc.arg(grant_id)
    AND (approval.all_deployments OR EXISTS(SELECT 1 FROM control.deployment_management_deployments allowed
        WHERE allowed.grant_id=approval.grant_id AND allowed.deployment_id=deployment.id))
    AND ((NOT url.ephemeral AND EXISTS (
        SELECT 1 FROM control.applied_project_services binding
        JOIN control.deployment_management_services selected ON selected.grant_id=approval.grant_id
            AND selected.capability='publish' AND selected.service=binding.service
            AND selected.protocol='http' AND selected.revoked_at IS NULL
        JOIN control.project_services declaration ON declaration.team_id=binding.team_id
            AND declaration.project_key=binding.project_key AND declaration.name=binding.service AND declaration.protocol=selected.protocol
        WHERE binding.group_id=deployment.id AND binding.team_id=approval.team_id
            AND binding.project_key=approval.project_key AND binding.public_url_id=url.id))
    OR (url.ephemeral AND approval.temporary_publication<>'' AND EXISTS (
        SELECT 1 FROM control.publisher_namespace_allocations allocation
        WHERE allocation.public_url_id=url.id AND allocation.publisher_grant_id=approval.grant_id
            AND allocation.deployment_id=deployment.id
            AND (url.access_mode='restricted' OR approval.temporary_publication='anonymous'))))
)::boolean;

-- name: FindDeploymentPublicationAllocation :one
SELECT public_url_id, deployment_id FROM control.publisher_namespace_allocations
WHERE publisher_identity_id=sqlc.arg(publisher_identity_id)
AND publisher_grant_id=sqlc.arg(publisher_grant_id) AND invocation_id=sqlc.arg(invocation_id);
