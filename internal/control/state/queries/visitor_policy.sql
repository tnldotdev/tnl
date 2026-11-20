-- name: ReadVisitorPolicyRevision :one
SELECT revision FROM control.visitor_policies WHERE resource_id=sqlc.arg(resource_id);

-- name: ReadVisitorPolicyEvents :many
SELECT revision,changed_at FROM control.visitor_policy_events
WHERE resource_id=sqlc.arg(resource_id) AND revision>sqlc.arg(after_revision)
ORDER BY revision LIMIT 256;

-- name: ReadVisitorVerificationKeyRevision :one
SELECT revision FROM control.visitor_verification_key_revision WHERE id=1;

-- name: ReadVisitorTokenIssuer :one
SELECT issuer FROM control.visitor_token_issuer WHERE id;

-- name: ReadVisitorPolicyService :one
SELECT * FROM control.services WHERE id=sqlc.arg(id);

-- name: HasVisitorPolicyRegisteredKeyCandidates :one
SELECT EXISTS (
    SELECT 1
    FROM control.applied_project_services binding
    JOIN control.deployment_management_services selected ON selected.team_id=binding.team_id AND selected.project_key=binding.project_key AND selected.service=binding.service AND selected.capability='connect' AND selected.revoked_at IS NULL
    WHERE binding.service_id=sqlc.arg(service_id)::text
);

-- name: ReadRegisteredKeyWatchVersion :one
-- an unbound service cannot gain a registered key from a change to another
-- service's project. the binding counter survives removal and recreation.
SELECT COALESCE(service.revision,0)::bigint AS binding_revision,
       COALESCE(project.revision,0)::bigint AS project_revision,
       COALESCE(team.revision,0)::bigint AS team_revision
FROM (SELECT sqlc.arg(service_id)::text AS id) request
LEFT JOIN control.applied_project_services binding ON binding.service_id=request.id
LEFT JOIN control.registered_key_watch_versions service ON (service.team_id,service.project_key,service.service_id)=('','',request.id)
LEFT JOIN control.registered_key_watch_versions project ON (project.team_id,project.project_key,project.service_id)=(binding.team_id,binding.project_key,'')
LEFT JOIN control.registered_key_watch_versions team ON (team.team_id,team.project_key,team.service_id)=(binding.team_id,'','');

-- name: ReadVisitorPolicyRegisteredKeys :many
SELECT approval.grant_id,signing.id AS key_id,current.public_key::bytea AS public_key,current.expires_at::timestamptz AS expires_at
FROM control.applied_project_services binding
JOIN control.deployment_management_services selected ON selected.team_id=binding.team_id AND selected.project_key=binding.project_key AND selected.service=binding.service AND selected.capability='connect' AND selected.revoked_at IS NULL
JOIN control.deployment_management_grants approval ON approval.grant_id=selected.grant_id
JOIN control.publisher_grants grant_record ON grant_record.id=approval.grant_id
JOIN control.publisher_identity_keys signing ON signing.publisher_identity_id=grant_record.publisher_identity_id AND signing.retired_at IS NULL
JOIN LATERAL control.deployment_connect_authority(approval.grant_id,signing.id,sqlc.arg(service_id),sqlc.arg(at_time)::timestamptz) current ON true
WHERE binding.service_id=sqlc.arg(service_id) ORDER BY approval.grant_id,signing.id LIMIT 4097;
