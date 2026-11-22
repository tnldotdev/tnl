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

-- name: ReadPublisherPolicyConfirmation :one
-- confirm only ordinary scopes without time-dependent parents.
-- every check, including the change bookmark, uses one statement snapshot.
SELECT watched.bookmark::text AS bookmark,issuer.issuer,service.certificate_hostname,
    CASE WHEN run.run_hostname<>'' AND run.certificate_expires_at IS NOT NULL
              AND control.service_run_alias_current(run.id,run.run_hostname)
         THEN run.run_hostname ELSE '' END::text AS alias_hostname,
    LEAST(sqlc.arg(max_until)::timestamptz,service.expires_at,run.serving_until,run.certificate_expires_at)::timestamptz AS valid_until
FROM control.service_runs run
JOIN control.services service ON service.id=run.service_id AND service.certificate_hostname=run.certificate_hostname
JOIN control.teams team ON team.id=service.team_id AND team.deleted_at IS NULL
JOIN control.publisher_run_policy_bookmarks watched ON watched.service_run_id=run.id
JOIN control.visitor_token_issuer issuer ON issuer.id
WHERE run.id=sqlc.arg(run_id) AND run.service_id=sqlc.arg(service_id)
    AND run.run_number=sqlc.arg(run_number) AND run.closed_at IS NULL AND run.started_at IS NOT NULL
    AND service.enabled AND service.deleted_at IS NULL AND service.guest_id IS NULL
    AND NOT EXISTS (SELECT 1 FROM control.workload_session_services w WHERE w.service_id=service.id)
    AND NOT EXISTS (
        SELECT 1 FROM control.applied_project_services binding
        JOIN control.deployment_management_services selected
            ON selected.team_id=binding.team_id AND selected.project_key=binding.project_key
            AND selected.service=binding.service AND selected.capability='connect' AND selected.revoked_at IS NULL
        WHERE binding.service_id=service.id
    )
    AND EXISTS (SELECT 1 FROM control.visitor_token_keys k WHERE k.retired_at IS NULL AND k.revoked_at IS NULL)
    AND NOT EXISTS (SELECT 1 FROM control.visitor_token_keys k WHERE k.retired_at IS NOT NULL AND k.revoked_at IS NULL);

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
